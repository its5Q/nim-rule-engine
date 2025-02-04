import std/tables

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

proc getOpConfig(op: Operation): tuple[argCount: int, argTypes: array[3, ArgType]] =
    case op
    of opInvalid:
        return (-2, [argNone, argNone, argNone])

    of opNoop:
        return (-1, [argNone, argNone, argNone])

    of opPassthrough, opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
        opReverse, opDuplicate, opReflect, opRotLeft, opRotRight, opTruncLeft, opTruncRight,
        opDupAll, opSwapBack, opSwapFront, opTitle, opAppendMem, opPrependMem, opMemorize,
        opRejectContainsMemory:

        return (0, [argNone, argNone, argNone])

    of opToggleAt, opDuplicateN, opDeleteAt, opTruncAt, opDupFirst, opDupLast, opBitwiseShiftLeft,
        opBitwiseShiftRight, opAsciiInc, opAsciiDec, opReplaceNMinus1, opReplaceNPlus1, 
        opDupBlockFront, opDupBlockBack, opRejectLess, opRejectGreater, opRejectEqual:

        return (1, [argInt, argNone, argNone])
    
    of opAppend, opPrepend, opPurge, opTitleSep, opRejectContain, opRejectNotContain, opRejectEqualFirst, opRejectEqualLast:

        return (1, [argChar, argNone, argNone])

    of opExtractRange, opOmitRange, opSwapAt:

        return (2, [argInt, argInt, argNone])

    of opInsertAt, opOverwriteAt, opToggleSep, opRejectEqualAt, opRejectContainsTimes:

        return (2, [argInt, argChar, argNone])

    of opReplace:

        return (2, [argChar, argChar, argNone])    

    of opExtractMem:

        return (3, [argChar, argChar, argChar])