when compileOption("profiler"):
  import std/nimprof

import std/[tables, sequtils, monotimes, times, strutils, algorithm, enumerate]

type 
    Operation {.size: 1.} = enum
        opInvalid, opNoop, opPassthrough, opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
        opToggleAt, opReverse, opDuplicate, opDuplicateN, opReflect, opRotLeft, opRotRight,
        opAppend, opPrepend, opTruncLeft, opTruncRight, opDeleteAt, opExtractRange, opOmitRange, opInsertAt,
        opOverwriteAt, opTruncAt, opReplace, opPurge, opDupFirst, opDupLast, opDupAll, opSwapFront, opSwapBack,
        opSwapAt, opBitwiseShiftLeft, opBitwiseShiftRight, opAsciiInc, opAsciiDec, opReplaceNPlus1,
        opReplaceNMinus1, opDupBlockFront, opDupBlockBack, opTitle, opTitleSep, opToggleSep,
        
        # Not supported (just like in hashcat with a rule-based attack on a GPU, keeping them for correct tokenization)
        opRejectLess, opRejectGreater, opRejectEqual, opRejectContain, opRejectNotContain, opRejectEqualFirst,
        opRejectEqualLast, opRejectEqualAt, opRejectContainsTimes, opRejectContainsMemory,
        opExtractMem, opAppendMem, opPrependMem, opMemorize

type 
    ArgType {.size: 1.} = enum
        argInt
        argChar
        argNone

type
    Token = object
        op: Operation
        arg1: char
        arg2: char
        arg3: char


const opTable = {
    ':': opPassthrough,         'l': opLowercase,            'u': opUppercase,
    'c': opCapitalize,          'C': opInvCapitalize,        't': opToggleCase,
    'T': opToggleAt,            'r': opReverse,              'd': opDuplicate,
    'p': opDuplicateN,          'f': opReflect,              '{': opRotLeft,
    '}': opRotRight,            '$': opAppend,               '^': opPrepend,
    '[': opTruncLeft,           ']': opTruncRight,           'D': opDeleteAt,
    'x': opExtractRange,        'O': opOmitRange,            'i': opInsertAt,
    'o': opOverwriteAt,         '\'': opTruncAt,             's': opReplace,
    '@': opPurge,               'z': opDupFirst,             'Z': opDupLast,
    'q': opDupAll,              'X': opExtractMem,           '4': opAppendMem,
    '6': opPrependMem,          'M': opMemorize,             '<': opRejectLess,
    '>': opRejectGreater,       '_': opRejectEqual,          '!': opRejectContain,
    '/': opRejectNotContain,    '(': opRejectEqualFirst,     ')': opRejectEqualLast,
    '=': opRejectEqualAt,       '%': opRejectContainsTimes,  'Q': opRejectContainsMemory,
    'k': opSwapFront,           'K': opSwapBack,             '*': opSwapAt,
    'L': opBitwiseShiftLeft,    'R': opBitwiseShiftRight,    '+': opAsciiInc,
    '-': opAsciiDec,            '.': opReplaceNPlus1,        ',': opReplaceNMinus1,
    'y': opDupBlockFront,       'Y': opDupBlockBack,         'E': opTitle, 
    'e': opTitleSep,            '3': opToggleSep,            ' ': opNoop
}.toTable


const opLUT = block:
    var result: array[256, Operation]

    for i in 0..255:
        result[i] = opTable.getOrDefault(chr(i), opInvalid)

    result

const opDecLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[int(opTable.getOrDefault(chr(i), opInvalid))] = chr(i)

    result    

# Those LUTs seem to be faster than those branchless versions I use to fill the table or built-in Nim functions
const toggleCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(i) xor (uint8( ( (uint8(i) or 0x20'u8) - ord('a') ) < 26 ) shl 5 ))

    result

const lowerCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(i) + (uint8(uint8(i) >= uint8('A') and uint8(i) <= uint8('Z')) shl 5))

    result

const upperCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(i) - (uint8(uint8(i) >= uint8('a') and uint8(i) <= uint8('z')) shl 5))

    result

const MAX_LENGTH = 255 # Default in hashcat --stdout

proc chrToInt(c: char): int {.inline.} =
    case c
    of '0'..'9':
        return int(uint8(c) - uint8('0'))
    of 'A'..'Z':
        return int(uint8(c) - uint8('A') + 10)
    else:
        return -1

proc intToChr(c: char): char {.inline.} =
    let n = uint8(c)
    case n
    of 0..9:
        return chr(uint8('0') + n)
    of 10..35:
        return chr(uint8('A') + n - 10)
    else:
        return '\xFF'


proc tokenizeRule*(rule: string, includeUnsupported: bool = true): seq[Token] = 
    var pos = 0
    var argCount: int
    var argTypes: array[3, ArgType] = [argNone, argNone, argNone]
    var args: array[3, char] = ['\0', '\0', '\0']

    if rule.len == 0 or rule[0] == '#':
        return

    while pos < len(rule) and len(result) < 31: # 31 is the maximum number of operations in a single rule supported in hashcat
        let op = opLUT[uint8(rule[pos])]
        case op
        of opInvalid:
            result.setLen(0)
            return

        of opNoop:
            inc pos
            continue

        of opPassthrough, opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
           opReverse, opDuplicate, opReflect, opRotLeft, opRotRight, opTruncLeft, opTruncRight,
           opDupAll, opSwapBack, opSwapFront, opTitle, opAppendMem, opPrependMem, opMemorize,
           opRejectContainsMemory:

            argCount = 0

        of opToggleAt, opDuplicateN, opDeleteAt, opTruncAt, opDupFirst, opDupLast, opBitwiseShiftLeft,
           opBitwiseShiftRight, opAsciiInc, opAsciiDec, opReplaceNMinus1, opReplaceNPlus1, 
           opDupBlockFront, opDupBlockBack, opRejectLess, opRejectGreater, opRejectEqual:
            argCount = 1
            argTypes = [argInt, argNone, argNone]
        
        of opAppend, opPrepend, opPurge, opTitleSep, opRejectContain, opRejectNotContain, opRejectEqualFirst, opRejectEqualLast:
            argCount = 1
            argTypes = [argChar, argNone, argNone]

        of opExtractRange, opOmitRange, opSwapAt:
            argCount = 2
            argTypes = [argInt, argInt, argNone]

        of opInsertAt, opOverwriteAt, opToggleSep, opRejectEqualAt, opRejectContainsTimes:
            argCount = 2
            argTypes = [argInt, argChar, argNone]

        of opReplace:
            argCount = 2
            argTypes = [argChar, argChar, argNone]        

        of opExtractMem:
            argCount = 3
            argTypes = [argChar, argChar, argChar]

        inc pos
        args = ['\0', '\0', '\0']
        for argN in 0..<argCount:
            if pos > high(rule):
                result.setLen(0)
                return

            if argTypes[argN] == argInt:
                let N = chrToInt(rule[pos])
                if N == -1:
                    result.setLen(0)
                    return
                args[argN] = chr(N)
                inc pos
            else:
                # Support for ASCII escape sequences for characters
                if unlikely(rule[pos] == '\\' and pos + 3 <= high(rule) and rule[pos + 1] == 'x'):
                    if not (rule[pos + 2] in HexDigits and rule[pos + 3] in HexDigits):
                        args[argN] = rule[pos]
                        inc pos
                    else:
                        args[argN] = chr(parseHexInt(rule[pos + 2..pos + 3]))
                        pos += 4
                else:
                    args[argN] = rule[pos]
                    inc pos

        if op >= opRejectLess and not includeUnsupported:
            result.setLen(0)
            return

        result.add Token(op: op, arg1: args[0], arg2: args[1], arg3: args[2])




# Separate function for multiple rules to eliminate overhead when calling from Python
proc tokenizeRules*(rules: seq[string], includeUnsupported: bool = true): seq[seq[Token]] =
    for i, rule in enumerate(rules):
        let tokenizedRule = tokenizeRule(rule, includeUnsupported)
        if unlikely(tokenizedRule.len == 0):
            # echo i + 1, ": ", rule
            continue

        result.add(tokenizedRule)


proc decodeRules*(rules: seq[seq[Token]]): seq[string] =
    # Turns tokenized rules back into plaintext
    for rule in rules:
        var strRule = newStringOfCap(128)
        var argCount: int
        var argTypes: array[3, ArgType] = [argNone, argNone, argNone]
        var args: array[3, char] = ['\0', '\0', '\0']
        for token in rule:
            if strRule.len > 0:
                strRule.add ' '

            case token.op
            of opInvalid:
                strRule = ""
                break

            of opNoop:
                continue

            of opPassthrough, opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
                opReverse, opDuplicate, opReflect, opRotLeft, opRotRight, opTruncLeft, opTruncRight,
                opDupAll, opSwapBack, opSwapFront, opTitle, opAppendMem, opPrependMem, opMemorize,
                opRejectContainsMemory:

                argCount = 0

            of opToggleAt, opDuplicateN, opDeleteAt, opTruncAt, opDupFirst, opDupLast, opBitwiseShiftLeft,
                opBitwiseShiftRight, opAsciiInc, opAsciiDec, opReplaceNMinus1, opReplaceNPlus1, 
                opDupBlockFront, opDupBlockBack, opRejectLess, opRejectGreater, opRejectEqual:
                argCount = 1
                argTypes = [argInt, argNone, argNone]
            
            of opAppend, opPrepend, opPurge, opTitleSep, opRejectContain, opRejectNotContain, opRejectEqualFirst, opRejectEqualLast:
                argCount = 1
                argTypes = [argChar, argNone, argNone]

            of opExtractRange, opOmitRange, opSwapAt:
                argCount = 2
                argTypes = [argInt, argInt, argNone]

            of opInsertAt, opOverwriteAt, opToggleSep, opRejectEqualAt, opRejectContainsTimes:
                argCount = 2
                argTypes = [argInt, argChar, argNone]

            of opReplace:
                argCount = 2
                argTypes = [argChar, argChar, argNone]        

            of opExtractMem:
                argCount = 3
                argTypes = [argChar, argChar, argChar]

            strRule.add opDecLUT[int(token.op)]
            
            args = [token.arg1, token.arg2, token.arg3]

            for i in 0..<argCount:
                if argTypes[i] == argInt:
                    strRule.add intToChr(args[i])
                else:
                    strRule.add args[i]
        
        result.add strRule


proc applyRule*(rule: seq[Token], mutatedPlain: var string) =
    for token in rule:
        #echo "Plain before processing token: ", mutatedPlain
        #echo "Processing token: ", token
        case token.op
        of opLowercase:
            for i in 0..high(mutatedPlain):
                mutatedPlain[i] = lowerCaseLUT[uint8(mutatedPlain[i])]
        of opUppercase:
            for i in 0..high(mutatedPlain):
                mutatedPlain[i] = upperCaseLUT[uint8(mutatedPlain[i])]
        of opCapitalize:
            if mutatedPlain.len == 0:
                continue

            for i in 1..high(mutatedPlain):
                mutatedPlain[i] = lowerCaseLUT[uint8(mutatedPlain[i])]

            mutatedPlain[0] = upperCaseLUT[uint8(mutatedPlain[0])]
        of opInvCapitalize:
            if mutatedPlain.len == 0:
                continue

            mutatedPlain[0] = lowerCaseLUT[uint8(mutatedPlain[0])]

            for i in 1..high(mutatedPlain):
                mutatedPlain[i] = upperCaseLUT[uint8(mutatedPlain[i])]
        of opToggleCase:
            for pos in 0..high(mutatedPlain):
                mutatedPlain[pos] = toggleCaseLUT[uint8(mutatedPlain[pos])]
        of opToggleAt:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = toggleCaseLUT[uint8(mutatedPlain[pos])]
        of opReverse:
            reverse(mutatedPlain)
        of opDuplicate:
            if unlikely(mutatedPlain.len * 2 > MAX_LENGTH):
                continue

            when defined(windows):
                let newLen = mutatedPlain.len * 2
                mutatedPlain.add mutatedPlain
                mutatedPlain.setLen(newLen) # Temporary fix for a bug in the compiler... https://github.com/nim-lang/Nim/issues/24664
            else:
                mutatedPlain.add mutatedPlain
        of opDuplicateN:
            if mutatedPlain.len == 0:
                continue

            let n = int(token.arg1)
            if unlikely((mutatedPlain.len * n + mutatedPlain.len) > MAX_LENGTH):
                continue

            mutatedPlain.add repeat(mutatedPlain, n)
        of opReflect:
            let l = mutatedPlain.len
            if l == 0 or l * 2 > MAX_LENGTH:
                continue            

            mutatedPlain.setLen(l * 2)
            for i in 0..<l:
                mutatedPlain[^(i + 1)] = mutatedPlain[i]
        of opRotLeft:
            if mutatedPlain.len > 1:
                let c = mutatedPlain[0]
                for i in 1..high(mutatedPlain):
                    mutatedPlain[i - 1] = mutatedPlain[i]
                mutatedPlain[^1] = c
        of opRotRight:
            if mutatedPlain.len > 1:
                let c = mutatedPlain[^1]
                for i in countdown(high(mutatedPlain) - 1, 0):
                    mutatedPlain[i + 1] = mutatedPlain[i]
                mutatedPlain[0] = c
        of opAppend:
            mutatedPlain.add token.arg1
        of opPrepend:
            mutatedPlain = token.arg1 & mutatedPlain
        of opTruncLeft:
            if mutatedPlain.len > 1:
                for i in 1..high(mutatedPlain):
                    mutatedPlain[i - 1] = mutatedPlain[i]

                mutatedPlain.setLen(mutatedPlain.len - 1)
                # mutatedPlain = mutatedPlain[1..^1]
            else:
                mutatedPlain.setLen(0)
        of opTruncRight:
            if mutatedPlain.len > 0:
                mutatedPlain.setLen(mutatedPlain.len - 1)
        of opDeleteAt:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            for i in pos..<high(mutatedPlain):
                mutatedPlain[i] = mutatedPlain[i + 1]

            mutatedPlain.setLen(mutatedPlain.len - 1)

            # delete(mutatedPlain, pos..pos)
        of opExtractRange:
            let pos = int(token.arg1)
            let count = int(token.arg2)
            if pos+count > mutatedPlain.len:
                continue
            
            if pos == 0:
                mutatedPlain.setLen(count)
            else:
                mutatedPlain = mutatedPlain[pos..<pos+count]
        of opOmitRange:
            if mutatedPlain.len == 0:
                continue

            let pos = int(token.arg1)
            let count = int(token.arg2)
            if pos+count > mutatedPlain.len:
                continue

            delete(mutatedPlain, pos..<pos+count)
        of opInsertAt:
            let pos = int(token.arg1)
            if pos > mutatedPlain.len:
                continue

            # if pos == mutatedPlain.len:
            #     mutatedPlain.add token.arg2
            # else:
            #     mutatedPlain = mutatedPlain[0..<pos] & token.arg2 & mutatedPlain[pos..^1]
            let sl = mutatedPlain.len
            mutatedPlain.setLen(sl + 1)
            var j = sl - 1
            while j >= pos:
                mutatedPlain[j+1] = mutatedPlain[j]
                dec j
            mutatedPlain[pos] = token.arg2
            # insert(mutatedPlain, $token.arg2, pos)
        of opOverwriteAt:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = token.arg2
        of opTruncAt:
            let pos = int(token.arg1)
            if pos > mutatedPlain.len:
                continue
            
            # mutatedPlain.setLen(pos) it's slower there for some reason, but not in opExtractRange??
            mutatedPlain = mutatedPlain[0..<pos]
        of opReplace:
            for i in 0..high(mutatedPlain):
                if mutatedPlain[i] == token.arg1:
                    mutatedPlain[i] = token.arg2
        of opPurge:
            if mutatedPlain.len == 0:
                continue

            # var newPlain = newStringUninit(mutatedPlain.len)
            # var newPos = 0
            # for c in mutatedPlain:
            #     if c != token.arg1:
            #         newPlain[newPos] = c
            #         inc newPos
            # newPlain.setLen(newPos)
            # mutatedPlain = newPlain

            var pos = 0
            for i in 0..high(mutatedPlain):
                if mutatedPlain[i] != token.arg1:
                    mutatedPlain[pos] = mutatedPlain[i]
                    inc pos
            mutatedPlain.setLen(pos)
        of opDupFirst:
            if mutatedPlain.len == 0:
                continue

            let count = int(token.arg1)
            mutatedPlain = repeat(mutatedPlain[0], count) & mutatedPlain
        of opDupLast:
            if mutatedPlain.len == 0:
                continue
            
            let count = int(token.arg1)
            mutatedPlain = mutatedPlain & repeat(mutatedPlain[^1], count)
        of opDupAll:
            if mutatedPlain.len == 0:
                continue

            var dupPlain = newStringUninit(mutatedPlain.len * 2)
            var ipos, opos: int
            while ipos < len(mutatedPlain):
                dupPlain[opos] = mutatedPlain[ipos]
                dupPlain[opos+1] = mutatedPlain[ipos]
                ipos += 1
                opos += 2
            mutatedPlain = dupPlain
        of opSwapFront:
            if mutatedPlain.len < 2:
                continue
            
            swap(mutatedPlain[0], mutatedPlain[1])
        of opSwapBack:
            if mutatedPlain.len < 2:
                continue
            
            swap(mutatedPlain[^2], mutatedPlain[^1])
        of opSwapAt:
            if mutatedPlain.len < 2:
                continue

            let pos1 = int(token.arg1)
            let pos2 = int(token.arg2)

            if pos1 > mutatedPlain.high or pos2 > mutatedPlain.high:
                continue

            swap(mutatedPlain[pos1], mutatedPlain[pos2])
        of opBitwiseShiftLeft:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) shl 1)
        of opBitwiseShiftRight:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) shr 1)
        of opAsciiInc:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) + 1)
        of opAsciiDec:
            let pos = int(token.arg1)
            if pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) - 1)
        of opReplaceNPlus1:
            let pos = int(token.arg1)
            if pos >= mutatedPlain.high:
                continue

            mutatedPlain[pos] = mutatedPlain[pos + 1]
        of opReplaceNMinus1:
            let pos = int(token.arg1)
            if pos == 0 or pos > mutatedPlain.high:
                continue

            mutatedPlain[pos] = mutatedPlain[pos - 1]
        of opDupBlockFront:
            let count = int(token.arg1)
            if count > mutatedPlain.len:
                continue

            mutatedPlain = mutatedPlain[0..<count] & mutatedPlain
        of opDupBlockBack:
            let count = int(token.arg1)
            if count > mutatedPlain.len:
                continue
            
            mutatedPlain.add mutatedPlain[^count..^1]
        of opTitle, opTitleSep:
            if mutatedPlain.len == 0:
                continue

            let sep = [' ', token.arg1][ord(token.op) - ord(opTitle)]

            var sepPositions: seq[int]
            var pos = 0
            while pos != -1 and pos < mutatedPlain.len:
                pos = mutatedPlain.find(sep, pos)

                if pos != -1:
                    sepPositions.add pos
                    inc pos

            #mutatedPlain = mutatedPlain.toLowerAscii
            for i in 0..high(mutatedPlain):
                mutatedPlain[i] = lowerCaseLUT[uint8(mutatedPlain[i])]
            
            mutatedPlain[0] = upperCaseLUT[uint8(mutatedPlain[0])]
            
            for pos in sepPositions:
                if pos + 1 < mutatedPlain.len:
                    mutatedPlain[pos + 1] = upperCaseLUT[uint8(mutatedPlain[pos + 1])]

        of opToggleSep:
            let target_n = int(token.arg1)
            var current_n = -1
            var pos = 0
            while pos < high(mutatedPlain):
                pos = mutatedPlain.find(token.arg2, pos)
                if likely(pos == -1):
                    break
                
                current_n += 1
                if current_n == target_n:
                    if pos + 1 > high(mutatedPlain):
                        break
                    mutatedPlain[pos + 1] = toggleCaseLUT[uint8(mutatedPlain[pos + 1])]
                    break

                inc pos
        else:
            continue


iterator applyRules*(rules: seq[seq[Token]], plains: seq[string]): string =
    for plain in plains:
        for rule in rules:
            var mutatedPlain = plain
            applyRule(rule, mutatedPlain)
            yield mutatedPlain


iterator getMatchingRules*(rules: seq[seq[Token]], plains: seq[string], target: string): (string, seq[Token]) =
    for plain in plains:
        for rule in rules:
            var mutatedPlain = plain
            # mutatedPlain.setLen(255)
            applyRule(rule, mutatedPlain)
            if mutatedPlain == target:
                yield (plain, rule)


proc main() =
    #let rule = tokenizeRule("$0 $0 $\\xC2 $\\xA3 clk", false)
    #echo rule
    #echo decodeRules(@[rule])
    #quit()

    var rules = lines("dedup.rule").toSeq

    var beginTime = getMonoTime()
    var tokenizedRules = tokenizeRules(rules, false)
    var endTime = getMonoTime()

    # quit()

    #for rule in tokenizedRules:
    #    echo rule

    #for candidate in applyRules(tokenizedRules, @["P@s$ w0rD-123!"]):
    #    echo candidate

    #quit()  

    echo "Spent on tokenization: ", (endTime - beginTime).inMilliseconds, " milliseconds"

    beginTime = getMonoTime()
    var decodedRules = decodeRules(tokenizedRules)
    endTime = getMonoTime()

    echo "Spent on decoding: ", (endTime - beginTime).inMilliseconds, " milliseconds"

    # var retokenizedRules = tokenizeRules(decodedRules, false)

    # for i in 0..high(tokenizedRules):
    #     if not (tokenizedRules[i] == retokenizedRules[i]):
    #         echo "Decoding error: "
    #         echo tokenizedRules[i]
    #         echo decodedRules[i]
    #         echo retokenizedRules[i]
    #         quit()

    # quit()

    for i in 1..10:
        beginTime = getMonoTime()
        # var plains = applyRules(tokenizedRules, @["P@s$ w0rD-123!", "123456789joao", "andreas_walter_"]).toSeq
        echo getMatchingRules(tokenizedRules, @["P@s$ w0rD-123!", "123456789joao", "andreas_walter_"], "walter_white").toSeq
        endTime = getMonoTime()

        echo "Spent on applying rules: ", (endTime - beginTime).inMilliseconds, " milliseconds"
        # echo int(plains.len / (endTime - beginTime).inMilliseconds * 1000), " candidates/s"


main()
