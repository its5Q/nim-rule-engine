when compileOption("profiler"):
  import std/nimprof

include constants
import std/[sequtils, monotimes, times, strutils, algorithm, enumerate, os]

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


iterator readLinesIter(filename: string): string =
    var f = open(filename, fmRead)
    defer: f.close

    var line: string
    while f.readLine(line):
        yield line


proc tokenizeRule*(rule: string, includeUnsupported: bool = true): seq[Token] = 
    ## Parses a single rule string into tokens
    var pos = 0
    var argCount: int
    var argTypes: array[3, ArgType] = [argNone, argNone, argNone]
    var args: array[3, char] = ['\0', '\0', '\0']

    if rule.len == 0 or rule[0] == '#':
        return

    while pos < len(rule) and len(result) < 31: # 31 is the maximum number of operations in a single rule supported in hashcat
        let op = opLUT[uint8(rule[pos])]

        (argCount, argTypes) = getOpConfig(op)
        inc pos

        if argCount == -1:
            continue
        elif unlikely(argCount == -2):
            result.setLen(0)
            return
        
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


proc tokenizeRules*(rules: seq[string], includeUnsupported: bool = true): seq[seq[Token]] =
    ## Tokenizes multiple string rules, exists to eliminate overhead when calling from Python
    for i, rule in enumerate(rules):
        let tokenizedRule = tokenizeRule(rule, includeUnsupported)
        if unlikely(tokenizedRule.len == 0):
            # echo i + 1, ": ", rule
            continue

        result.add(tokenizedRule)


proc decodeRule*(rule: seq[Token]): string =
    ## Accepts a single tokenized rule and returns it decoded back into string form
    var argCount: int
    var argTypes: array[3, ArgType] = [argNone, argNone, argNone]
    var args: array[3, char] = ['\0', '\0', '\0']
    for token in rule:
        if result.len > 0:
            result.add ' '

        (argCount, argTypes) = getOpConfig(token.op)

        if argCount == -1:
            continue
        elif unlikely(argCount == -2):
            result.setLen(0)
            return

        result.add opDecLUT[int(token.op)]
        args = [token.arg1, token.arg2, token.arg3]

        for i in 0..<argCount:
            if argTypes[i] == argInt:
                result.add intToChr(args[i])
            else:
                result.add args[i]


proc decodeRules*(rules: seq[seq[Token]]): seq[string] =
    ## Accepts multiple tokenized rules and returns them decoded back into string form
    for rule in rules:        
        result.add decodeRule(rule)


proc applyRule*(rule: seq[Token], mutatedPlain: var string) =
    ## Accepts a single rule and a string by reference to be mutated by that rule
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
    ## An iterator that applies a list of tokenized rules to multiple plains and yields them one by one
    for plain in plains:
        for rule in rules:
            var mutatedPlain = plain
            applyRule(rule, mutatedPlain)
            yield mutatedPlain


iterator getMatchingRules*(rules: seq[seq[Token]], plains: seq[string], target: string): (string, seq[Token]) =
    ## An iterator that applies a list of tokenized rules to multiple plains and yield the rules that match the specified target string
    for plain in plains:
        for rule in rules:
            var mutatedPlain = plain
            # mutatedPlain.setLen(255)
            applyRule(rule, mutatedPlain)
            if mutatedPlain == target:
                yield (plain, rule)
    

when isMainModule:
    import cligen

    proc generateCandidatesCli(rules_file: string = "", rule: string = "", plain: string = "", plains_file: string = "") = 
        ## Generates password candidates with specified rules. Either a rule file path or a single rule must be specified.
        ## If no plain or plain file path is provided, the plains will be read from stdin.
        if rules_file.isEmptyOrWhitespace and rule.isEmptyOrWhitespace:
            writeLine(stderr, "No rule or rule file has been specified. See help for details.")
            quit()

        var mutatedPlain: string
        var tokenizedRules: seq[seq[Token]]

        if not rule.isEmptyOrWhitespace:
            var tokenizedRule = tokenizeRule(rule, false)
            if tokenizedRule.len > 0:
                tokenizedRules.add tokenizedRule
            else:
                writeLine(stderr, "Skipping empty or invalid rule: " & rule)
        else:
            if not fileExists(rules_file):
                writeLine(stderr, "Rules file doesn't exist, quitting.")
                quit(2)

            for ruleLine in readLinesIter(rules_file):
                var tokenizedRule = tokenizeRule(ruleLine, false)
                if tokenizedRule.len > 0:
                    tokenizedRules.add tokenizedRule
                else:
                    writeLine(stderr, "Skipping empty or invalid rule: " & ruleLine)
                
        if not plain.isEmptyOrWhitespace:
            for rule in tokenizedRules:
                mutatedPlain = plain
                applyRule(rule, mutatedPlain)
                if mutatedPlain.len > 0:
                    writeLine(stdout, mutatedPlain)
        elif not plains_file.isEmptyOrWhitespace:
            var mutatedPlain: string
            if not fileExists(plains_file):
                writeLine(stderr, "Plains file doesn't exist, quitting.")
                quit(2)

            for plain in readLinesIter(plains_file):
                for rule in tokenizedRules:
                    mutatedPlain = plain
                    applyRule(rule, mutatedPlain)
                    if mutatedPlain.len > 0:
                        writeLine(stdout, mutatedPlain)
        else:
            var origPlain: string
            while stdin.readLine(origPlain):
                for rule in tokenizedRules:
                    mutatedPlain = origPlain
                    applyRule(rule, mutatedPlain)
                    if mutatedPlain.len > 0:
                        writeLine(stdout, mutatedPlain)

        flushFile(stdout)


    proc normalizeRulesCli(rules_file: string = "") = 
        ## Parses input rules and normalizes them by splitting each function in a rule by a single space, skipping invalid or unsupported rules.
        var inputFile: File
        if not rules_file.isEmptyOrWhitespace:
            if not fileExists(rules_file):
                writeLine(stderr, "Rules file doesn't exist, quitting.")
                quit(2)
            
            inputFile = open(rules_file, fmRead)
        else:
            inputFile = stdin

        var ruleLine: string
        while inputFile.readLine(ruleLine):
            var tokenizedRule = tokenizeRule(ruleLine, false)
            if tokenizedRule.len > 0:
                writeLine(stdout, decodeRule(tokenizedRule))
            else:
                writeLine(stderr, "Skipping empty or invalid rule: " & ruleLine)

        flushFile(stdout)


    proc benchmarkCli(rules_file: string) = 
        ## Measures tokenization, decoding and rule matching speed on a specified rules file
        if not fileExists(rules_file):
            writeLine(stderr, "Rules files doesn't exists, quitting")
            quit(2)

        var rules = readLinesIter(rules_file).toSeq

        var beginTime = getMonoTime()
        var tokenizedRules = tokenizeRules(rules, false)
        var endTime = getMonoTime()

        var spent = (endTime - beginTime).inMicroseconds

        echo "Spent on tokenization: ", spent / 1000, " milliseconds"
        echo "Speed: ", float(tokenizedRules.len) / (spent / 1000000), " rules/s"
        echo()

        beginTime = getMonoTime()
        var decodedRules = decodeRules(tokenizedRules)
        endTime = getMonoTime()

        spent = (endTime - beginTime).inMicroseconds

        echo "Spent on decoding: ", spent / 1000, " milliseconds"
        echo "Speed: ", float(tokenizedRules.len) / (spent / 1000000), " rules/s"
        echo()

        var totalSpent = 0
        for i in 1..10:
            beginTime = getMonoTime()
            discard getMatchingRules(tokenizedRules, @["pxpxeif/f5t12", "kc9o0m3*", "h!*2Ting!!2!"], "Ling!!!!").toSeq
            endTime = getMonoTime()

            spent = (endTime - beginTime).inMicroseconds
            totalSpent += spent

            echo "(Iteration ", i , ") Spent on matching rules: ", spent / 1000, " milliseconds"
            echo int(((tokenizedRules.len * 3) / spent) * 1000000), " candidates/s"
            echo()

        echo "Average matching speed: ", int((float(tokenizedRules.len * 3) / (totalSpent / 10)) * 1000000), " candidates/s"


    proc matchingRulesCli(rules_file: string, target: string, plain: string = "", plains_file: string = "") = 
        ## Finds and outputs rules that match the target string when applied to plains. If plains_file is specified, all plains are loaded into memory.
        var mutatedPlain: string
        var tokenizedRules: seq[seq[Token]]
        var plains: seq[string]

        if not fileExists(rules_file):
            writeLine(stderr, "Rules file doesn't exist, quitting.")
            quit(2)

        for ruleLine in readLinesIter(rules_file):
            var tokenizedRule = tokenizeRule(ruleLine, false)
            if tokenizedRule.len > 0:
                tokenizedRules.add tokenizedRule
            else:
                writeLine(stderr, "Skipping empty or invalid rule: " & ruleLine)
        

        if not plain.isEmptyOrWhitespace:
            plains = @[plain]
        elif not plains_file.isEmptyOrWhitespace:
            if not fileExists(plains_file):
                writeLine(stderr, "Plains file doesn't exist, quitting.")
                quit(2)

            for plain in readLinesIter(plains_file):
                plains.add plain

        if plains.len > 0:
            for _, matchedRule in getMatchingRules(tokenizedRules, plains, target):
                writeLine(stdout, decodeRule(matchedRule))
        else:
            var plain: string
            while stdin.readLine(plain):
                for _, matchedRule in getMatchingRules(tokenizedRules, @[plain], target):
                    writeLine(stdout, decodeRule(matchedRule))

        flushFile(stdout)
    
    dispatchMulti(
        [
            generateCandidatesCli, 
            cmdName = "gen", 
            short={"rules_file": 'r', "rule": 'j', "plain": 'p', "plains_file": 'f'},
            help={
                "rules_file": "Path to a file with hashcat rules. Either this or the --rule argument must be specified",
                "rule": "A single hashcat rule to be used", "plain": "A single plaintext to be mutated",
                "plains_file": "Path to a file with a list of plains to be mutated"
            }
        ],
        [
            normalizeRulesCli,
            cmdName = "normalize",
            short={"rules_file": 'r'},
            help={
                "rules_file": "Path to a rules file to be normalized. stdin if not specified" 
            }
        ],
        [benchmarkCli],
        [
            matchingRulesCli,
            cmdName = "match",
            short={"rules_file": 'r', "plain": 'p', "plains_file": 'f', "target": 't'},
            help={
                "rules_file": "Path to a rules file to be used for matching",
                "plains_file": "Path to a file with a list of plains to be mutated and matched against the target. If plains_file or plain are not specified, plains are read from stdin",
                "target": "The target string for the rules to match"
            }
        ]
    ) 
