when compileOption("profiler"):
  import std/nimprof
import std/[tables, sequtils, monotimes, times, strutils, algorithm]

type 
    Operation {.size : 1} = enum
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


# I don't know if it's actually faster to construct a lookup table instead of just using a table of char -> int, but let's make a LUT anyway
# TODO: benchmark against regular table
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

proc chrToInt(c: char): int8 =
    case c
    of '0'..'9':
        return int8(c) - int8('0')
    of 'A'..'Z':
        return int8(c) - int8('A') + 10
    else:
        return 0


proc tokenizeRule*(rule: string): seq[Token] = 
    var pos = 0
    while pos < len(rule) and rule[pos] != '#' and len(result) < 31: # 31 is the maximum amount of rules supported in hashcat
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

        of opToggleAt, opDuplicateN, opAppend, opPrepend, opDeleteAt, opTruncAt, opPurge, opDupFirst,
           opDupLast, opRejectLess, opRejectGreater, opRejectEqual, opRejectContain, opRejectNotContain,
           opRejectEqualFirst, opRejectEqualLast, opBitwiseShiftLeft, opBitwiseShiftRight, opAsciiInc,
           opAsciiDec, opReplaceNMinus1, opReplaceNPlus1, opDupBlockFront, opDupBlockBack, opTitleSep:

            if pos + 1 >= len(rule):
                result.setLen(0)
                return

            result.add Token(op: op, arg1: rule[pos+1], arg2: '\0', arg3: '\0')
            pos += 2

        of opExtractRange, opOmitRange, opInsertAt, opOverwriteAt, opReplace, opRejectEqualAt,
           opRejectContainsTimes, opSwapAt, opToggleSep:

            if pos + 2 >= len(rule):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: rule[pos+1], arg2: rule[pos+2], arg3: '\0')
            pos += 3

        of opExtractMem:
            if pos + 3 >= len(rule):
                result.setLen(0)
                return
            
            result.add Token(op: op, arg1: rule[pos+1], arg2: rule[pos+2], arg3: rule[pos+3])
            pos += 4


# Separate function for multiple rules to eliminate overhead when calling from Python
proc tokenizeRules*(rules: seq[string]): seq[seq[Token]] =
    for rule in rules:
        let tokenizedRule = tokenizeRule(rule)
        if tokenizedRule.len == 0:
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
                    mutatedPlain = mutatedPlain.toLowerAscii
                of opUppercase:
                    mutatedPlain = mutatedPlain.toUpperAscii
                of opCapitalize:
                    mutatedPlain = mutatedPlain.toLowerAscii.capitalizeAscii
                of opInvCapitalize:
                    if mutatedPlain.len <= 1:
                        mutatedPlain = mutatedPlain.toLowerAscii
                    else:
                        mutatedPlain = mutatedPlain[0].toLowerAscii & mutatedPlain.toUpperAscii[1..^1]
                of opToggleCase:
                    for pos in 0..high(mutatedPlain):
                        mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) xor (uint8( ( (uint8(mutatedPlain[pos]) or 0x20'u8) - ord('a') ) < 26 ) shl 5 ))
                of opToggleAt:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) xor (uint8( ( (uint8(mutatedPlain[pos]) or 0x20'u8) - ord('a') ) < 26 ) shl 5 ))
                of opReverse:
                    reverse(mutatedPlain)
                of opDuplicate:
                    mutatedPlain.add mutatedPlain
                of opDuplicateN:
                    let n = chrToInt(token.arg1)
                    mutatedPlain.add repeat(mutatedPlain, n)
                of opReflect:
                    mutatedPlain.add reversed(mutatedPlain).join
                of opRotLeft:
                    if mutatedPlain.len > 1:
                        mutatedPlain = mutatedPlain[1..^1] & mutatedPlain[0]
                of opRotRight:
                    if mutatedPlain.len > 1:
                        mutatedPlain = mutatedPlain[^1] & mutatedPlain[0..^2]
                of opAppend:
                    mutatedPlain = mutatedPlain & token.arg1
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
                    let pos = int(chrToInt(token.arg1))
                    if pos > mutatedPlain.high:
                        continue

                    delete(mutatedPlain, pos..pos)
                of opExtractRange:
                    let pos = chrToInt(token.arg1)
                    let count = chrToInt(token.arg2)
                    if pos+count > mutatedPlain.len:
                        continue
                    mutatedPlain = mutatedPlain[pos..<pos+count]
                of opOmitRange:
                    let pos = int(chrToInt(token.arg1))
                    let count = chrToInt(token.arg2)
                    if pos+count > mutatedPlain.len:
                        continue

                    delete(mutatedPlain, pos..<pos+count)
                of opInsertAt:
                    let pos = chrToInt(token.arg1)
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
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = token.arg2
                of opTruncAt:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.len:
                        continue

                    mutatedPlain = mutatedPlain[0..<pos]
                of opReplace:
                    mutatedPlain = mutatedPlain.replace(token.arg1, token.arg2)
                of opPurge:
                    mutatedPlain = mutatedPlain.replace($token.arg1, "")
                of opDupFirst:
                    if mutatedPlain.len == 0:
                        continue

                    let count = chrToInt(token.arg1)
                    mutatedPlain = repeat(mutatedPlain[0], count) & mutatedPlain
                of opDupLast:
                    if mutatedPlain.len == 0:
                        continue
                    
                    let count = chrToInt(token.arg1)
                    mutatedPlain = mutatedPlain & repeat(mutatedPlain[^1], count)
                of opDupAll:
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
                    let pos1 = chrToInt(token.arg1)
                    let pos2 = chrToInt(token.arg2)

                    if pos1 > mutatedPlain.high or pos2 > mutatedPlain.high:
                        continue

                    var t = mutatedPlain[pos1]
                    mutatedPlain[pos1] = mutatedPlain[pos2]
                    mutatedPlain[pos2] = t
                of opBitwiseShiftLeft:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) shl 1)
                of opBitwiseShiftRight:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) shr 1)
                of opAsciiInc:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) + 1)
                of opAsciiDec:
                    let pos = chrToInt(token.arg1)
                    if pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = chr(uint8(mutatedPlain[pos]) - 1)
                of opReplaceNPlus1:
                    let pos = chrToInt(token.arg1)
                    if pos >= mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = mutatedPlain[pos + 1]
                of opReplaceNMinus1:
                    let pos = chrToInt(token.arg1)
                    if pos == 0 or pos > mutatedPlain.high:
                        continue

                    mutatedPlain[pos] = mutatedPlain[pos - 1]
                of opDupBlockFront:
                    let count = chrToInt(token.arg1)
                    if count > mutatedPlain.len:
                        continue

                    mutatedPlain = mutatedPlain[0..<count] & mutatedPlain
                of opDupBlockBack:
                    let count = chrToInt(token.arg1)
                    if count > mutatedPlain.len:
                        continue
                    
                    mutatedPlain.add mutatedPlain[^count..^1]
                of opTitle, opTitleSep:
                    var sep: char
                    if token.op == opTitle:
                        sep = ' '
                    else:
                        sep = token.arg1

                    mutatedPlain = mutatedPlain.toLowerAscii.capitalizeAscii
                    var pos = 0
                    while true:
                        pos = mutatedPlain.find(sep, pos)
                        if pos == -1:
                            break
                        
                        mutatedPlain[pos + 1] = mutatedPlain[pos + 1].toUpperAscii
                        inc pos
                of opToggleSep:
                    let target_n = chrToInt(token.arg1)
                    var current_n = -1
                    var pos = 0
                    while true:
                        pos = mutatedPlain.find(token.arg2, pos)
                        if pos == -1:
                            break
                        
                        current_n += 1
                        if current_n == target_n:
                            mutatedPlain[pos + 1] = chr(uint8(mutatedPlain[pos + 1]) xor (uint8( ( (uint8(mutatedPlain[pos + 1]) or 0x20'u8) - ord('a') ) < 26 ) shl 5 ))
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
    var rules = lines("A:\\Coding Projects\\Other\\hashcat-log-rules\\other-rules\\dedup.rule").toSeq

    var beginTime = getMonoTime()
    var tokenizedRules = tokenizeRules(rules)
    var endTime = getMonoTime()

    echo "Spent on tokenization: ", (endTime - beginTime).inMilliseconds, " milliseconds"

    for i in 1..10:
        beginTime = getMonoTime()
        var plains = applyRules(tokenizedRules, @["P@s$ w0rD-123!"])
        endTime = getMonoTime()

        echo "Spent on applying rules: ", (endTime - beginTime).inMilliseconds, " milliseconds"


main()
