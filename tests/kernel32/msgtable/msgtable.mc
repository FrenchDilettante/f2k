; /*
;  * msgtable.mc - the msgtable fixture's message table, part of its
;  * source: tests\build.bat compiles it with MSVC 6's message compiler
;  * (mc -U msgtable.mc: msgtable.rc, msgtable.h and MSG00409.bin, the
;  * texts stored in Unicode as cmd.exe's are), then rc msgtable.rc, and
;  * links msgtable.res into msgtable.exe.
;  *
;  * mc keeps each text line and ends it with CR LF; FormatMessage reads
;  * the escapes (%n, %%, %0...) and the inserts. msgtable.c defines the
;  * same ids by hand (it does not include msgtable.h): change both
;  * together. The ids sit in two blocks, 0x100-0x10A and 0x200, so a
;  * lookup crosses the table's blocks and 0x150 falls in the gap.
;  */

MessageIdTypedef=DWORD

LanguageNames=(English=0x409:MSG00409)

; /* Plain text over two lines: the regular line breaks are CR LF. */
MessageId=0x100
SymbolicName=MSG_PLAIN
Language=English
The first line of a plain message.
Its second line, after a regular line break.
.

; /* One short line, for the buffer sizes. */
MessageId=0x101
SymbolicName=MSG_SHORT
Language=English
Short message.
.

; /* String inserts, one used twice; 0x102 (258) is a system message too. */
MessageId=0x102
SymbolicName=MSG_INSERTS
Language=English
Inserts: %1, %2, and %1 again.
.

; /* Numeric inserts, printf-style formats between exclamation marks. */
MessageId=0x103
SymbolicName=MSG_NUMBERS
Language=English
Numbers: %1!d!, %2!08lX!, %3!u!, [%4!5d!], [%5!-5d!], %6!x!.
.

; /* s is the call's own width (WCHAR in FormatMessageW), S the other. */
MessageId=0x104
SymbolicName=MSG_WIDTHS
Language=English
Strings: %1!s! (the call's width), %2!S! (the other).
.

; /* Width and precision from the arguments: %1 reads three, %5 two. */
MessageId=0x105
SymbolicName=MSG_STAR
Language=English
Star: [%1!*.*s!] %4 [%5!*s!]
.

; /* The escapes: %% %n %r %. %! %t and percent-space. */
MessageId=0x106
SymbolicName=MSG_ESCAPES
Language=English
100%% sure.%nA hard break before this, and a%rcarriage return.
%.
A lone period above; %! is an exclamation mark, then%ta tab, a forced% space.
.

; /* A prompt: %0 ends the text with no line break. */
MessageId=0x107
SymbolicName=MSG_PROMPT
Language=English
Are you sure about %1 (Y/N)? %0
.

; /* Nothing but %0: an empty message. */
MessageId=0x108
SymbolicName=MSG_EMPTY
Language=English
%0
.

; /* The first line ends in a blank (keep it). */
MessageId=0x109
SymbolicName=MSG_BLANK
Language=English
This line ends in a blank: 
and this one does not.
.

; /* A long line to wrap, with a word longer than the small widths. */
MessageId=0x10A
SymbolicName=MSG_LONG
Language=English
A long line of words to wrap at a small width, with supercalifragilisticexpialidocious, a word longer than some widths, inside it.
A second line after a regular break,%nand one after a hard break.
.

; /* The second block of ids. */
MessageId=0x200
SymbolicName=MSG_SECOND
Language=English
From the second block of ids.
.
