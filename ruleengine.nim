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
    Token = object
        op: Operation
        arg1: char
        arg2: char
        arg3: char


const opLUT = block:
    var result: array[256, Operation]

    var opTable: Table[char, Operation] = {
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

    for i in 0..255:
        result[i] = opTable.getOrDefault(chr(i), opInvalid)

    result

# Those LUTs seem to be faster than those branchless versions I use to fill the table or built-in Nim functions
const toggleCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(result[i]) xor (uint8( ( (uint8(result[i]) or 0x20'u8) - ord('a') ) < 26 ) shl 5 ))

    result

const lowerCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(result[i]) + (uint8(uint8(result[i]) >= uint8('A') and uint8(result[i]) <= uint8('Z')) shl 5))

    result

const upperCaseLUT = block:
    var result: array[256, char]

    for i in 0..255:
        result[i] = chr(uint8(result[i]) - (uint8(uint8(result[i]) >= uint8('a') and uint8(result[i]) <= uint8('z')) shl 5))

    result


proc chrToInt(c: char): uint8 =
    case c
    of '0'..'9':
        return uint8(c) - uint8('0')
    of 'A'..'Z':
        return uint8(c) - uint8('A') + 10
    else:
        return 0


proc tokenizeRule*(rule: string): seq[Token] = 
    var pos = 0
    while pos < len(rule) and rule[pos] != '#' and len(result) < 31: # 31 is the maximum amount of operations in a single rule supported in hashcat
        let op = opLUT[uint8(rule[pos])]
        case op

        of opInvalid:
            result.setLen(0)
            return

        of opNoop, opPassthrough:
            pos += 1

        of opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
           opReverse, opDuplicate, opReflect, opRotLeft, opRotRight, opTruncLeft, opTruncRight,
           opDupAll, opAppendMem, opPrependMem, opMemorize, opRejectContainsMemory, opSwapBack,
           opSwapFront, opTitle:

            result.add Token(op: op, arg1: '\0', arg2: '\0', arg3: '\0')
            pos += 1

        of opToggleAt, opDuplicateN, opDeleteAt, opTruncAt, opDupFirst, opDupLast, opRejectLess,
           opRejectGreater, opRejectEqual, opBitwiseShiftLeft, opBitwiseShiftRight, opAsciiInc,
           opAsciiDec, opReplaceNMinus1, opReplaceNPlus1, opDupBlockFront, opDupBlockBack:

            if unlikely(pos + 1 > high(rule)):
                result.setLen(0)
                return

            result.add Token(op: op, arg1: chr(chrToInt(rule[pos+1])), arg2: '\0', arg3: '\0')
            pos += 2
        
        of opAppend, opPrepend, opPurge, opRejectContain, opRejectNotContain,
           opRejectEqualFirst, opRejectEqualLast, opTitleSep:

            if unlikely(pos + 1 > high(rule)):
                result.setLen(0)
                return

            result.add Token(op: op, arg1: rule[pos+1], arg2: '\0', arg3: '\0')
            pos += 2

        of opExtractRange, opOmitRange, opSwapAt:

            if unlikely(pos + 2 >= len(rule)):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: chr(chrToInt(rule[pos+1])), arg2: chr(chrToInt(rule[pos+2])), arg3: '\0')
            pos += 3

        of opInsertAt, opOverwriteAt, opRejectEqualAt, opRejectContainsTimes, opToggleSep:

            if unlikely(pos + 2 >= len(rule)):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: chr(chrToInt(rule[pos+1])), arg2: rule[pos+2], arg3: '\0')
            pos += 3

        of opReplace:

            if unlikely(pos + 2 >= len(rule)):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: rule[pos+1], arg2: rule[pos+2], arg3: '\0')
            pos += 3


        of opExtractMem:
            if unlikely(pos + 3 >= len(rule)):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: rule[pos+1], arg2: rule[pos+2], arg3: rule[pos+3])
            pos += 4


# Separate function for multiple rules to eliminate overhead when calling from Python
proc tokenizeRules*(rules: seq[string]): seq[seq[Token]] =
    for rule in rules:
        let tokenizedRule = tokenizeRule(rule)
        if unlikely(tokenizedRule.len == 0):
            continue

        result.add(tokenizedRule)


proc applyRules*(rules: seq[seq[Token]], plains: seq[string]): seq[string] =
    for plain in plains:
        for rule in rules:
            var mutatedPlain = plain
            #echo "Applying rule: ", rule
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

                    for i in 0..high(mutatedPlain):
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
                    mutatedPlain.add mutatedPlain
                of opDuplicateN:
                    if mutatedPlain.len == 0:
                        continue

                    let n = int(token.arg1)
                    mutatedPlain.add repeat(mutatedPlain, n)
                of opReflect:
                    if mutatedPlain.len == 0:
                        continue

                    var reversed = mutatedPlain
                    reverse(reversed)
                    mutatedPlain.add reversed
                of opRotLeft:
                    if mutatedPlain.len > 1:
                        mutatedPlain = mutatedPlain[1..^1] & mutatedPlain[0]
                of opRotRight:
                    if mutatedPlain.len > 1:
                        mutatedPlain = mutatedPlain[^1] & mutatedPlain[0..^2]
                of opAppend:
                    mutatedPlain.add token.arg1
                of opPrepend:
                    mutatedPlain = token.arg1 & mutatedPlain
                of opTruncLeft:
                    if mutatedPlain.len > 1:
                        mutatedPlain = mutatedPlain[1..^1]
                    else:
                        mutatedPlain.setLen(0)
                of opTruncRight:
                    if mutatedPlain.len > 0:
                        mutatedPlain.setLen(mutatedPlain.len - 1)
                of opDeleteAt:
                    let pos = int(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    delete(mutatedPlain, pos..pos)
                of opExtractRange:
                    let pos = int(token.arg1)
                    let count = int(token.arg2)
                    if pos+count > mutatedPlain.len:
                        continue
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

                    mutatedPlain = mutatedPlain[0..<pos]
                of opReplace:
                    mutatedPlain = mutatedPlain.replace(token.arg1, token.arg2)
                of opPurge:
                    if mutatedPlain.len == 0:
                        continue

                    var newPlain = newStringUninit(mutatedPlain.len)
                    var newPos = 0
                    for c in mutatedPlain:
                        if c != token.arg1:
                            newPlain[newPos] = c
                            inc newPos
                    newPlain.setLen(newPos)
                    mutatedPlain = newPlain
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

                    var t = mutatedPlain[1]
                    mutatedPlain[1] = mutatedPlain[0]
                    mutatedPlain[0] = t
                of opSwapBack:
                    if mutatedPlain.len < 2:
                        continue

                    var t = mutatedPlain[^1]
                    mutatedPlain[^1] = mutatedPlain[^2]
                    mutatedPlain[^2] = t
                of opSwapAt:
                    if mutatedPlain.len < 2:
                        continue

                    let pos1 = int(token.arg1)
                    let pos2 = int(token.arg2)

                    if pos1 > mutatedPlain.high or pos2 > mutatedPlain.high:
                        continue

                    var t = mutatedPlain[pos1]
                    mutatedPlain[pos1] = mutatedPlain[pos2]
                    mutatedPlain[pos2] = t
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

                    #mutatedPlain = mutatedPlain.toLowerAscii
                    for i in 0..high(mutatedPlain):
                        mutatedPlain[i] = lowerCaseLUT[uint8(mutatedPlain[i])]
                    
                    mutatedPlain[0] = upperCaseLUT[uint8(mutatedPlain[0])]
                    var pos = 0
                    while true:
                        pos = mutatedPlain.find(sep, pos)
                        if likely(pos == -1):
                            break
                        
                        mutatedPlain[pos + 1] = upperCaseLUT[uint8(mutatedPlain[pos + 1])]
                        inc pos
                of opToggleSep:
                    let target_n = int(token.arg1)
                    var current_n = -1
                    var pos = 0
                    while true:
                        pos = mutatedPlain.find(token.arg2, pos)
                        if likely(pos == -1):
                            break
                        
                        current_n += 1
                        if current_n == target_n:
                            mutatedPlain[pos + 1] = toggleCaseLUT[uint8(mutatedPlain[pos + 1])]
                            break

                        inc pos
                else:
                    continue

            result.add mutatedPlain

    result


proc main() =
    #var line: string
    #while readLine(stdin, line):
    #    echo applyRules(@[tokenizeRule(line)], @["p@ss-w0-rd123 "])
    var rules = lines("dedup.rule").toSeq

    var beginTime = getMonoTime()
    var tokenizedRules = tokenizeRules(rules)
    var endTime = getMonoTime()

    echo "Spent on tokenization: ", (endTime - beginTime).inMilliseconds, " milliseconds"

    for i in 1..10:
        beginTime = getMonoTime()
        var plains = applyRules(tokenizedRules, @["P@s$ w0rD-123!", "123456789joao", "andreas_walter_"])
        endTime = getMonoTime()

        echo "Spent on applying rules: ", (endTime - beginTime).inMilliseconds, " milliseconds"
        echo int(plains.len / (endTime - beginTime).inMilliseconds * 1000), " candidates/s"


main()
