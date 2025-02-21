# ANTI-DISASSEMBLY

## Lab 15-1:

1. The Jump Instruction with a Constant Condition technique.
2. `E8` which is the first byte of the 5-bytes call opcode.
3. [5] times.
4. `pdq`.
___

## Lab 15-2:

1. http://www.practicalmalwareanalysis.com/bamboo.html
2. The original one is `DESKTOP-M87PSAK` but the binary encode it by adding `1` to each char and replace `Z` and `9` with `A` and `0` which will produce `EFTLUPQ.N98QTBL`.
3. `Bamboo::` and `::`
4. It will connect to another URL and download some data named `Account Summary.xls.exe` then execute it using `ShellExecute`.
___

## Lab 15.3:
1. by overwriting the ret address of the main function
2. sits a handler which will be used after executing division by zero, the handler will connect to a URL then download a file from it then execute it using `WINEXEC`.
3. http://www.practicalmalwareanalysis.com/tt.html
4. spoolsrv.exe
___
___