import std/tables

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


proc tokenizeRule*(rule: string): seq[Token] = 
    var pos = 0
    while pos < len(rule) and rule[pos] != '#' and len(result) < 31: # 31 is the maximum amount of rules supported in hashcat
        let op = opLUT[ord(rule[pos])]
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




                
        


        



proc main() =
    echo tokenizeRule(":")

main()
