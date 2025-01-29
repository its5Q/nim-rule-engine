import std/tables

type 
    Operation {.size : 1} = enum
        opNoop, opPassthrough, opLowercase, opUppercase, opCapitalize, opInvCapitalize, opToggleCase,
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


# I don't know if it's actually faster to construct a lookup table instead of just using a table of char -> int, but let's make a LUT anyway
const operationsTable = block:
    var result: array[256, Operation]

    var opTable: Table[char, Operation] = {
        ':': opPassthrough, 'l': opLowercase, 'u': opUppercase, 'c': opCapitalize, 'C': opInvCapitalize,
        't': opToggleCase, 'T': opToggleAt, 'r': opReverse # TODO: finish
    }.toTable

    for i in 0..255:
        result[i] = opTable.getOrDefault(chr(i), opNoop)

    result


