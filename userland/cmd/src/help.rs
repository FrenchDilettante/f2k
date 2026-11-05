//! What `/?` prints: cmd.exe's own help (`cmd /?`), and each built-in command's, printed in place
//! of running it when a word of its arguments starts with `/?` (`cd x /?`), or its first one for
//! `echo`, `set` and `rem` (see [`requested`]).
//!
//! Each text is laid out as Windows' `/?` texts are: a sentence saying what the command does, the
//! syntax lines, the parameters each on its line, their descriptions aligned in a column, then
//! notes. The words are F2K's own, and say what F2K's shell does. Lines are wrapped to fit 79
//! columns and end with CR LF.

use core::fmt;

use crate::{
    command_start,
    command_word,
    is_blank,
    is_delimiter,
    is_named,
    skip_blanks,
    Command,
    State,
    QUOTE,
};

/// The columns a help line fits in: an 80-column console's, less the last, so that no line wraps
/// on its own.
pub const WIDTH: usize = 79;

/// The blanks before a parameter's name, and between the longest name and the descriptions.
const INDENT: usize = 2;

/// One command's help.
#[derive(Debug)]
pub struct Help {
    /// The names the command goes by, lowercase (`cd` and `chdir`).
    pub names: &'static [&'static str],
    /// What the command does, in a sentence.
    pub summary: &'static str,
    /// The syntax lines, as printed: each starts with one of the command's names, in capitals,
    /// except a line starting with blanks, which goes on with the line before it.
    pub syntax: &'static [&'static str],
    /// The parameters (switches, arguments, codes) and what each does, in the order shown.
    pub parameters: &'static [(&'static str, &'static str)],
    /// Paragraphs after the parameters.
    pub notes: &'static [&'static str],
}

/// `cmd /?`: the shell's own command line (see src/switches.rs).
pub static CMD: Help = Help {
    names: &["cmd"],
    summary: "Starts F2K's command interpreter, which runs built-in commands, programs and \
              batch files.",
    syntax: &[
        "CMD [/Q] [/S] [/A | /U] [/D] [/E:ON | /E:OFF] [/F:ON | /F:OFF] [/V:ON | /V:OFF]",
        "    [/T:fg] [[/C | /K] string]",
    ],
    parameters: &[
        (
            "/C",
            "Runs string, then ends, with its last command's return code.",
        ),
        ("/K", "Runs string, then goes on reading commands."),
        (
            "/Q",
            "Starts with echo off: no prompt, and batch file lines are not shown.",
        ),
        (
            "/S",
            "Removes the first and the last quote of string, whatever it holds.",
        ),
        (
            "/A",
            "Writes to a file or a pipe in the OEM code page (the default).",
        ),
        (
            "/U",
            "Writes to a file or a pipe in Unicode (UTF-16LE). Programs write their own way.",
        ),
        ("/D", "Accepted and ignored: there is no AutoRun command."),
        (
            "/E:ON, /E:OFF",
            "Accepted and ignored: command extensions are always on.",
        ),
        (
            "/F:ON, /F:OFF",
            "Accepted and ignored: there is no file name completion.",
        ),
        (
            "/V:ON, /V:OFF",
            "Accepted and ignored: there is no delayed expansion.",
        ),
        (
            "/T:fg",
            "Accepted and ignored: the colors stay as they are.",
        ),
        ("string", "The command line to run."),
    ],
    notes: &[
        "A switch is / and a letter, in either case, and switches may run together (/q/c). /C \
         and /K end the switches: the rest of the line, its leading blanks skipped, is string. \
         Without either, the shell shows its banner and prompts for commands.",
        "The quotes in string are kept when there is no /S, string holds exactly two quotes, \
         there is a blank between them and none of &<>()@^|, and the text between them names a \
         program file. Otherwise, when string starts with a quote, that quote and the last one \
         are removed.",
    ],
};

/// Every built-in command's help, one entry per command, by its names. The commands the shell
/// does not have yet are here too: their help shows once the shell runs them as built-ins.
pub static HELP: &[Help] = &[
    Help {
        names: &["call"],
        summary: "Runs a batch file from another one, then goes on with the line after the \
                  call.",
        syntax: &[
            "CALL [drive:][path]filename [arguments]",
            "CALL :label [arguments]",
        ],
        parameters: &[
            (
                "filename",
                "The batch file to run, looked for as a program is.",
            ),
            (
                "arguments",
                "What the batch file sees as %1 to %9, and all of them as %*.",
            ),
            (
                ":label",
                "Runs the batch file from the line after the label, as a batch file of its \
                 own: %0 is :label, its arguments its own, and EXIT /B or GOTO :EOF come back.",
            ),
        ],
        notes: &[
            "The line after CALL has its %variables% replaced a second time, then runs: a \
             program or a built-in command as it would without CALL. ERRORLEVEL becomes what it \
             returns: a batch file's ERRORLEVEL, a program's exit code, 0 for a built-in command \
             that succeeds. CALL alone fails.",
            "In a batch file, %0 is its name as typed, and %~1 to %~9 are its arguments without \
             the quotes around them. %~f1 is the first argument as a full path, %~d1 its drive, \
             %~p1 its directory, %~n1 its name, %~x1 its extension, %~s1 its short (8.3) path, \
             %~a1 its attributes, %~t1 the date and time it was last written and %~z1 its size; \
             the letters combine (%~dp0, %~snx1, %~ftza1).",
        ],
    },
    Help {
        names: &["cd", "chdir"],
        summary: "Shows the current directory, or changes it.",
        syntax: &[
            "CHDIR [/D] [drive:][path]",
            "CHDIR ..",
            "CD [/D] [drive:][path]",
            "CD ..",
        ],
        parameters: &[
            (
                "/D",
                "Changes the current drive too, as changing the directory does.",
            ),
            (
                "path",
                "The directory to change to, taken as typed: blanks are part of it, and quotes \
                 are not removed.",
            ),
            ("..", "The parent of the current directory."),
        ],
        notes: &[
            "CD alone prints the current directory. When the directory cannot be changed, CD \
             says so and sets ERRORLEVEL to 1.",
        ],
    },
    Help {
        names: &["cls"],
        summary: "Clears the console's screen.",
        syntax: &["CLS"],
        parameters: &[],
        notes: &[
            "When the output is not a console, CLS writes a form feed instead. Words after it \
             are ignored; a switch is refused.",
        ],
    },
    Help {
        names: &["color"],
        summary: "Sets the console's text and background colors.",
        syntax: &["COLOR [attr]"],
        parameters: &[(
            "attr",
            "Two hexadecimal digits: the background's color, then the text's.",
        )],
        notes: &[
            "The digits name these colors: 0 black, 1 blue, 2 green, 3 aqua, 4 red, 5 purple, \
             6 yellow, 7 white, 8 gray, 9 light blue, A light green, B light aqua, C light red, \
             D light purple, E light yellow, F bright white.",
            "COLOR alone goes back to the colors the console started with. Two equal digits \
             change nothing, and set ERRORLEVEL to 1.",
        ],
    },
    Help {
        names: &["copy"],
        summary: "Copies files, or joins several into one.",
        syntax: &[
            "COPY [/Y | /-Y] [/A | /B] source [/A | /B]",
            "     [+ source [/A | /B] [+ ...]] [destination [/A | /B]]",
        ],
        parameters: &[
            ("source", "A file to copy; wildcards select several."),
            (
                "/A",
                "Treats the file as text: it ends at its first Ctrl+Z.",
            ),
            ("/B", "Treats the file as binary: all of it is copied."),
            (
                "destination",
                "The directory, or the file name, the copies go to.",
            ),
            ("/Y", "Replaces an existing file without asking."),
            ("/-Y", "Asks before replacing an existing file."),
        ],
        notes: &[
            "Sources joined by + are appended, in turn, into one destination file. The COPYCMD \
             variable may hold /Y or /-Y, which the command line overrides. COPY asks before \
             replacing a file only when it runs at the prompt, not in a batch file.",
        ],
    },
    Help {
        names: &["date"],
        summary: "Shows the date, or sets it.",
        syntax: &["DATE [/T | date]"],
        parameters: &[
            ("/T", "Prints the date, without asking for a new one."),
            ("date", "The new date, as month, day and year: mm-dd-yy."),
        ],
        notes: &["DATE alone shows the date and asks for a new one; an empty line keeps it."],
    },
    Help {
        names: &["del", "erase"],
        summary: "Deletes files.",
        syntax: &[
            "DEL [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names",
            "ERASE [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names",
        ],
        parameters: &[
            (
                "names",
                "The files to delete, one or more, wildcards allowed. A directory stands for \
                 every file in it.",
            ),
            ("/P", "Asks before each file is deleted."),
            ("/F", "Deletes read-only files too."),
            (
                "/S",
                "Deletes the matching files in every subdirectory too.",
            ),
            (
                "/Q",
                "Never asks, not even when every file in a directory is to go.",
            ),
            (
                "/A",
                "Deletes only the files with the attributes listed: R read-only, H hidden, \
                 S system, A ready for archiving. A - before a letter selects the files without \
                 that attribute.",
            ),
        ],
        notes: &[],
    },
    Help {
        names: &["dir"],
        summary: "Lists the files and subdirectories in a directory.",
        syntax: &[
            "DIR [drive:][path][filename] [/A[[:]attributes]] [/B] [/C] [/D] [/L] [/N]",
            "  [/O[[:]sortorder]] [/P] [/Q] [/S] [/T[[:]timefield]] [/W] [/X] [/4]",
        ],
        parameters: &[
            (
                "[drive:][path][filename]",
                "The directory, or the files, to list; wildcards select several. Without it, \
                 the current directory.",
            ),
            (
                "/A",
                "Lists the entries with the attributes given: D directories, R read-only, \
                 H hidden, A ready for archiving, S system. A - before a letter lists the \
                 entries without that attribute. /A alone lists every entry; without /A, \
                 hidden and system files are left out.",
            ),
            (
                "/B",
                "Lists the names alone, without headings or totals (full paths with /S).",
            ),
            (
                "/C",
                "Shows the sizes with a thousands separator, as without it. /-C shows them \
                 without.",
            ),
            ("/D", "As /W, the entries sorted down the columns."),
            ("/L", "Shows the names in lowercase."),
            (
                "/N",
                "The long format, the names on the right: always the one shown.",
            ),
            (
                "/O",
                "Lists the entries sorted: N by name, E by extension, S by size (smallest \
                 first), D by date and time (oldest first), G directories first. A - before \
                 a letter reverses its order. /O alone is /O:GN.",
            ),
            ("/P", "Pauses after each screenful."),
            ("/Q", "Accepted and ignored: owners are not shown."),
            (
                "/S",
                "Lists the matching entries in every subdirectory too, then their totals.",
            ),
            (
                "/T",
                "The time shown, and sorted by: C creation, A last access, W last written \
                 (the default).",
            ),
            (
                "/W",
                "Lists the names side by side, directories in brackets.",
            ),
            (
                "/X",
                "Shows each entry's short name before its name, or blanks for a name that is \
                 one itself.",
            ),
            ("/4", "Shows years with four digits, as without it."),
        ],
        notes: &[
            "The DIRCMD variable may hold switches, which the command line overrides. A - \
             after the / turns a switch off: /-W, /-O.",
        ],
    },
    Help {
        names: &["echo"],
        summary: "Prints a line of text, or turns the echo of commands on or off.",
        syntax: &["ECHO [ON | OFF]", "ECHO [message]", "ECHO."],
        parameters: &[
            (
                "ON, OFF",
                "Turns echo on or off. With echo off, the shell shows no prompt, and a batch \
                 file's lines are not shown before they run.",
            ),
            ("message", "The text to print, as typed."),
        ],
        notes: &[
            "ECHO alone shows whether echo is on, and ECHO. prints an empty line. A line \
             starting with @ is not echoed, whatever the echo.",
        ],
    },
    Help {
        names: &["exit"],
        summary: "Ends the command interpreter, or the batch file it runs.",
        syntax: &["EXIT [/B] [exitCode]"],
        parameters: &[
            (
                "/B",
                "Ends the batch file instead of the shell. Outside a batch file, the shell \
                 ends.",
            ),
            (
                "exitCode",
                "The number the shell ends with; with /B in a batch file, the ERRORLEVEL it \
                 leaves.",
            ),
        ],
        notes: &[
            "Without exitCode, EXIT ends the shell with the ERRORLEVEL, and EXIT /B in a batch \
             file leaves the ERRORLEVEL as it is.",
        ],
    },
    Help {
        names: &["for"],
        summary: "Runs a command once for each file, word, number or line of a set.",
        syntax: &[
            "FOR %variable IN (set) DO command",
            "FOR /D %variable IN (set) DO command",
            "FOR /R [[drive:]path] %variable IN (set) DO command",
            "FOR /L %variable IN (start,step,end) DO command",
            "FOR /F [\"options\"] %variable IN (file-set) DO command",
            "FOR /F [\"options\"] %variable IN (\"string\") DO command",
            "FOR /F [\"options\"] %variable IN ('command') DO command",
        ],
        parameters: &[
            (
                "%variable",
                "One character, its case counting. In a batch file it is written %%variable.",
            ),
            (
                "set",
                "Words separated by blanks, commas, semicolons or equals signs. A word with * \
                 or ? stands for the files it matches, hidden and system ones left out.",
            ),
            (
                "command",
                "What runs each time, the rest of the line, & and | included, with %variable \
                 replaced.",
            ),
            (
                "/D",
                "The words with * or ? match directories instead of files.",
            ),
            (
                "/R",
                "The set is looked for in the directory path (the current one without it), \
                 then in each directory below it; a word without * or ? is joined to each \
                 directory's full path.",
            ),
            (
                "/L",
                "Counts from start, by step, until it passes end: (1,1,5) is 1 to 5, (5,-1,1) \
                 5 down to 1.",
            ),
            (
                "/F",
                "Reads lines: from the files of file-set, from string, or from what command \
                 writes, run by a CMD /C of its own. Empty lines are skipped.",
            ),
        ],
        notes: &[
            "The options of /F, in one quoted string: eol=c skips the lines starting with c \
             (; without it); skip=n skips the first n lines; delims=xxx are the characters \
             between the tokens of a line (a blank and a tab without it; put it last to have \
             a blank among them); tokens=x,y,m-n hands the variable and the letters after it \
             the tokens asked for (the first without it), a * at the end handing the next one \
             the rest of the line; usebackq reads \"file\" as a file name, 'string' as a \
             string and `command` as a command.",
            "%~variable is the value without its quotes, and %~ with the letters f, d, p, n, \
             x, s, a, t and z its full path, drive, directory, name, extension, short path, \
             attributes, time of its last write and size, as with a batch file's %~1; %~$PATH:variable is the full path of the first file \
             of that name in PATH's directories, empty when there is none.",
            "While echo is on, each command runs after the prompt and its text, unless it \
             starts with @.",
        ],
    },
    Help {
        names: &["goto"],
        summary: "Goes on with the batch file's line after a label.",
        syntax: &["GOTO label"],
        parameters: &[(
            "label",
            "The label, a line of the batch file starting with a colon and the label's word.",
        )],
        notes: &[
            "The label is looked for from the line after GOTO to the end of the batch file, \
             then from its start, whatever the case of its letters. A label that is not there \
             ends the batch file.",
            "GOTO :EOF ends the batch file, or the part of it CALL :label runs.",
        ],
    },
    Help {
        names: &["if"],
        summary: "Runs a command when a condition holds, or another when it does not.",
        syntax: &[
            "IF [NOT] ERRORLEVEL number command",
            "IF [/I] [NOT] string1==string2 command",
            "IF [NOT] EXIST filename command",
            "IF [/I] string1 compare-op string2 command",
            "IF [NOT] DEFINED variable command",
            "IF [NOT] CMDEXTVERSION number command",
            "IF condition (command) ELSE command",
        ],
        parameters: &[
            ("NOT", "Runs the command when the condition does not hold."),
            ("ERRORLEVEL", "Holds when the ERRORLEVEL is number or more."),
            (
                "==",
                "Holds when the two strings are the same text, quotes included.",
            ),
            (
                "EXIST",
                "Holds when a file or directory goes by filename (* and ? allowed).",
            ),
            (
                "compare-op",
                "EQU, NEQ, LSS, LEQ, GTR or GEQ: equal, not equal, less, less or equal, \
                 greater, greater or equal. Two numbers compare as numbers (010 is octal, \
                 0x10 hexadecimal), anything else as text.",
            ),
            ("/I", "Compares text whatever the case of its letters."),
            ("DEFINED", "Holds when the environment has the variable."),
            (
                "CMDEXTVERSION",
                "Holds when the command extensions' version, 2, is number or more.",
            ),
            (
                "command",
                "The rest of the line, & and | included, or the commands in parentheses \
                 before ELSE.",
            ),
        ],
        notes: &[
            "ELSE must follow the closing parenthesis on its line; the command after it takes \
             the rest of the line. Commands in parentheses may span lines, in a batch file or \
             after More? at the prompt: their variables are replaced as each line is read, \
             before any of them runs.",
        ],
    },
    Help {
        names: &["md", "mkdir"],
        summary: "Creates a directory.",
        syntax: &["MKDIR [drive:]path", "MD [drive:]path"],
        parameters: &[("path", "The directory to create.")],
        notes: &["The directories missing along the path are created too."],
    },
    Help {
        names: &["move"],
        summary: "Moves files, or renames a directory.",
        syntax: &[
            "MOVE [/Y | /-Y] [drive:][path]filename1[,...] destination",
            "MOVE [/Y | /-Y] [drive:][path]dirname1 dirname2",
        ],
        parameters: &[
            (
                "filename1",
                "A file to move; several are separated by commas, and wildcards select several.",
            ),
            (
                "destination",
                "Where the files go: a directory, or, for one file, its new name.",
            ),
            ("dirname1", "The directory to rename."),
            ("dirname2", "Its new name."),
            ("/Y", "Replaces an existing file without asking."),
            ("/-Y", "Asks before replacing an existing file."),
        ],
        notes: &[
            "The COPYCMD variable may hold /Y or /-Y, which the command line overrides. MOVE \
             asks before replacing a file only when it runs at the prompt, not in a batch file.",
        ],
    },
    Help {
        names: &["path"],
        summary: "Shows or sets the directories programs are looked for in.",
        syntax: &["PATH [[drive:]path[;...][;%PATH%]]", "PATH ;"],
        parameters: &[
            (
                "path",
                "A directory to look in; several are separated by semicolons.",
            ),
            (
                "%PATH%",
                "The directories already set, added to the new ones.",
            ),
            (";", "Alone, deletes the PATH variable."),
        ],
        notes: &[
            "PATH alone shows the PATH variable. The current directory is looked in first, \
             before PATH's directories.",
        ],
    },
    Help {
        names: &["pause"],
        summary: "Asks for a key to be pressed, and waits for it.",
        syntax: &["PAUSE"],
        parameters: &[],
        notes: &[],
    },
    Help {
        names: &["popd"],
        summary: "Changes back to the directory PUSHD saved last, and forgets it.",
        syntax: &["POPD"],
        parameters: &[],
        notes: &[],
    },
    Help {
        names: &["prompt"],
        summary: "Changes what the shell prompts with.",
        syntax: &["PROMPT [text]"],
        parameters: &[
            (
                "text",
                "The new prompt: its characters, with these codes replaced.",
            ),
            ("$A", "& (ampersand)"),
            ("$B", "| (vertical bar)"),
            ("$C", "( (left parenthesis)"),
            ("$D", "The date"),
            ("$E", "The escape character (code 27)"),
            ("$F", ") (right parenthesis)"),
            ("$G", "> (greater-than sign)"),
            ("$H", "A backspace: the character before is erased"),
            ("$L", "< (less-than sign)"),
            ("$M", "Nothing: there are no network drives"),
            ("$N", "The current drive"),
            ("$P", "The current drive and directory"),
            ("$Q", "= (equal sign)"),
            ("$S", "A space"),
            ("$T", "The time"),
            ("$V", "F2K's version"),
            ("$_", "A line break"),
            ("$$", "$ (dollar sign)"),
            ("$+", "One + for each directory PUSHD has saved"),
        ],
        notes: &[
            "The codes are read in either case. PROMPT alone goes back to the default prompt, \
             $P$G.",
        ],
    },
    Help {
        names: &["pushd"],
        summary: "Saves the current directory, then changes to another one.",
        syntax: &["PUSHD [path | ..]"],
        parameters: &[("path", "The directory to change to.")],
        notes: &[
            "POPD changes back to the saved directory. PUSHD alone lists the saved \
             directories, the last saved first.",
        ],
    },
    Help {
        names: &["rd", "rmdir"],
        summary: "Removes a directory.",
        syntax: &["RMDIR [/S] [/Q] [drive:]path", "RD [/S] [/Q] [drive:]path"],
        parameters: &[
            ("path", "The directory to remove."),
            (
                "/S",
                "Removes the files and subdirectories it holds too; without it, the directory \
                 must be empty.",
            ),
            ("/Q", "With /S, removes them without asking."),
        ],
        notes: &[],
    },
    Help {
        names: &["rem"],
        summary: "Marks a remark: the line does nothing.",
        syntax: &["REM [comment]"],
        parameters: &[],
        notes: &[
            "In a batch file with echo on, a REM line is shown before it runs; a line starting \
             with :: is a label, and is never shown.",
        ],
    },
    Help {
        names: &["ren", "rename"],
        summary: "Renames files.",
        syntax: &[
            "RENAME [drive:][path]filename1 filename2",
            "REN [drive:][path]filename1 filename2",
        ],
        parameters: &[
            ("filename1", "The file to rename; wildcards select several."),
            ("filename2", "The new name."),
        ],
        notes: &["The new name takes no drive or path: the file stays where it is."],
    },
    Help {
        names: &["set"],
        summary: "Shows, sets or deletes environment variables.",
        syntax: &[
            "SET [variable=[string]]",
            "SET \"variable=string\"",
            "SET /A expression",
            "SET /P variable=[promptString]",
        ],
        parameters: &[
            ("variable", "The variable's name."),
            (
                "string",
                "Its value; nothing after the = deletes the variable.",
            ),
            (
                "/A",
                "Evaluates expression, a calculation on 32-bit signed integers.",
            ),
            (
                "/P",
                "Prints promptString, then sets the variable to a line read from the input.",
            ),
        ],
        notes: &[
            "SET alone lists every variable. SET and a name with no = lists the variables \
             whose names start with it. In the quoted form, the value ends at the last quote.",
            "SET /A's operators, the tightest first: ( ) grouping; ! ~ - (not, bitwise not, \
             negation); * / % (in a batch file, %% for %); + -; << >> (shifts); & (and); ^ \
             (exclusive or); | (or); = *= /= %= += -= &= ^= |= <<= >>= (assignments); and , \
             between expressions. Any other word is a variable's name, its value read as a \
             number (0 when it is not set). Numbers are decimal (17), hexadecimal (0x11) or \
             octal (021). Quote an expression that holds & | ^ < or >. At the prompt, SET /A \
             prints the last expression's value; in a batch file it prints nothing.",
            "SET /P with an empty line, or none, leaves the variable as it is and sets \
             ERRORLEVEL to 1.",
            "Before a line runs, each %variable% in it is replaced by the variable's value. \
             %variable:~offset,count% is part of the value: offset characters are skipped, then \
             count kept (the rest without ,count). A negative offset counts from the end, and a \
             negative count leaves out that many at the end.",
            "%variable:old=new% is the value with each old replaced by new, whatever the case of \
             its letters; %variable:*old=new% replaces everything up to the first old.",
            "These names have a value even when no variable is set by them: %CD%, %DATE%, \
             %TIME%, %RANDOM%, %ERRORLEVEL%, %CMDEXTVERSION% and %CMDCMDLINE%.",
        ],
    },
    Help {
        names: &["shift"],
        summary: "Moves a batch file's arguments down one: %1 takes %2's value, and so on.",
        syntax: &["SHIFT [/n]"],
        parameters: &[(
            "/n",
            "Starts at %n (a digit from 0 to 8): the arguments before it stay.",
        )],
        notes: &["%0 takes %1's value without /n. %* is not changed."],
    },
    Help {
        names: &["start"],
        summary: "Starts a program, or a command, without waiting for it to end.",
        syntax: &[
            "START [\"title\"] [/Dpath] [/I] [/MIN] [/MAX] [/SEPARATE | /SHARED]",
            "      [/LOW | /NORMAL | /HIGH | /REALTIME | /ABOVENORMAL | /BELOWNORMAL]",
            "      [/WAIT] [/B] [command/program] [parameters]",
        ],
        parameters: &[
            (
                "\"title\"",
                "A title for a new window. Accepted and ignored: the program shares this \
                 console.",
            ),
            ("/Dpath", "The directory the program starts in."),
            (
                "/I",
                "Accepted and ignored: the program gets the shell's environment as it is.",
            ),
            (
                "/MIN, /MAX",
                "Accepted and ignored: there is no new window.",
            ),
            (
                "/SEPARATE, /SHARED",
                "Accepted and ignored: there are no 16-bit programs.",
            ),
            ("/LOW", "Starts the program in the idle priority class."),
            ("/NORMAL", "Starts it in the normal priority class."),
            ("/HIGH", "Starts it in the high priority class."),
            ("/REALTIME", "Starts it in the realtime priority class."),
            (
                "/ABOVENORMAL",
                "Starts it in the above normal priority class.",
            ),
            (
                "/BELOWNORMAL",
                "Starts it in the below normal priority class.",
            ),
            (
                "/WAIT",
                "Waits for the program to end; its exit code becomes the ERRORLEVEL.",
            ),
            (
                "/B",
                "Starts the program in this console, as START always does here.",
            ),
            (
                "command/program",
                "The program, looked for as the shell looks for one. A built-in command or \
                 a batch file runs in a shell of its own, CMD /K, which stays once it is done.",
            ),
            ("parameters", "What the program gets on its command line."),
        ],
        notes: &[
            "The first quoted word is the title: START \"\" \"C:\\a b\\x.exe\" starts a program \
             whose name is in quotes. START alone starts a shell.",
        ],
    },
    Help {
        names: &["time"],
        summary: "Shows the time, or sets it.",
        syntax: &["TIME [/T | time]"],
        parameters: &[
            ("/T", "Prints the time, without asking for a new one."),
            ("time", "The new time, as hours:minutes:seconds.hundredths."),
        ],
        notes: &["TIME alone shows the time and asks for a new one; an empty line keeps it."],
    },
    Help {
        names: &["title"],
        summary: "Sets the console window's title.",
        syntax: &["TITLE [string]"],
        parameters: &[("string", "The new title.")],
        notes: &[],
    },
    Help {
        names: &["type"],
        summary: "Writes files' contents to the output, as they are.",
        syntax: &["TYPE [drive:][path]filename [...]"],
        parameters: &[(
            "filename",
            "A file to write. Several are separated by blanks; a name in quotes may hold \
             blanks.",
        )],
        notes: &[
            "With several files, each one's name comes before it, on the standard error, so \
             that the output holds the files alone.",
        ],
    },
    Help {
        names: &["ver"],
        summary: "Shows F2K's version.",
        syntax: &["VER"],
        parameters: &[],
        notes: &[],
    },
];

/// The help of the built-in command `word` names, whatever its case: None for a word that names
/// none.
pub fn of(word: &[u16]) -> Option<&'static Help> {
    HELP.iter()
        .find(|help| help.names.iter().any(|name| is_named(word, name)))
}

/// The `/?` text starts with.
const SWITCH: [u16; 2] = [b'/' as u16, b'?' as u16];

/// Whether some word of `argument`, outside quotes, starts with `/?` (`cd x /?`, `cd /?x`): words
/// are separated by blanks and by `,` `;` `=`.
fn asks_anywhere(argument: &[u16]) -> bool {
    let mut quoted = false;
    let mut start = true;
    for (at, &unit) in argument.iter().enumerate() {
        if unit == QUOTE {
            quoted = !quoted;
        }
        if !quoted && start && argument[at..].starts_with(&SWITCH) {
            return true;
        }
        start = !quoted && is_delimiter(unit);
    }
    false
}

/// The help to print in place of running `line`, which [`crate::parse`] read as `command`, as
/// Windows 2000's cmd finds it:
/// - `echo`'s when the text after its blank starts with `/?` (`echo /?x`; not `echo x /?`, nor
///   `echo./?`, whose `/?` is text);
/// - `set`'s and `rem`'s when their first argument starts with `/?` (`set /?x`);
/// - any other built-in's when one of its words starts with `/?`, wherever it is (`cd x /?`,
///   `cd,/?`); `call`'s for `call cd /?`, the `/?` being in call's words.
///
/// A program's line (`x.exe /?`) is the program's to read.
pub fn requested(line: &[u16], command: &Command<'_>) -> Option<&'static Help> {
    let line = command_start(line);
    match command {
        Command::Empty | Command::Run { .. } => None,
        Command::Echo(_) => {
            let text = line
                .get(5..)
                .filter(|_| line.get(4).is_some_and(|&unit| is_blank(unit)))?;
            skip_blanks(text)
                .starts_with(&SWITCH)
                .then(|| of(&line[..4]))
                .flatten()
        }
        _ => {
            let (word, rest) = command_word(line);
            let asks = match command {
                Command::Set(_) | Command::Remark => skip_blanks(rest).starts_with(&SWITCH),
                _ => asks_anywhere(rest),
            };
            if asks {
                of(word)
            } else {
                None
            }
        }
    }
}

/// The return code of a command whose help was printed: 1, as Windows 2000's cmd's (`cmd /c cd
/// /?` ends with 1); `rem`'s is 0. Neither touches the ERRORLEVEL, and neither does `cmd /?`,
/// which ends the shell with [`SHOWN`].
pub fn answered(command: &Command<'_>, state: &mut State) {
    state.return_code = if *command == Command::Remark {
        0
    } else {
        SHOWN
    };
}

/// The return code a help printed leaves, and `cmd /?`'s exit code.
pub const SHOWN: u32 = 1;

/// `text`'s words written from `column`, wrapped to [`WIDTH`]: a line that would run past it
/// breaks before its word, and the next starts `indent` blanks in.
fn wrapped(
    f: &mut fmt::Formatter<'_>,
    text: &str,
    mut column: usize,
    indent: usize,
) -> fmt::Result {
    // Whether the line has no word yet.
    let mut first = true;
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        if !first && column + 1 + word.len() > WIDTH {
            write!(f, "\r\n{:indent$}", "")?;
            column = indent;
            first = true;
        }
        if !first {
            f.write_str(" ")?;
            column += 1;
        }
        f.write_str(word)?;
        column += word.len();
        first = false;
    }
    f.write_str("\r\n")
}

impl fmt::Display for Help {
    /// The help as printed: the summary, the syntax lines, the parameters, the notes, each part
    /// after an empty line, every line ending with CR LF.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wrapped(f, self.summary, 0, 0)?;
        f.write_str("\r\n")?;
        for line in self.syntax {
            write!(f, "{line}\r\n")?;
        }
        if !self.parameters.is_empty() {
            f.write_str("\r\n")?;
            let width = self
                .parameters
                .iter()
                .map(|(name, _)| name.len())
                .max()
                .unwrap_or(0);
            let column = INDENT + width + INDENT;
            for (name, description) in self.parameters {
                write!(f, "{:INDENT$}{name:width$}{:INDENT$}", "", "")?;
                wrapped(f, description, column, column)?;
            }
        }
        for note in self.notes {
            f.write_str("\r\n")?;
            wrapped(f, note, 0, 0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The help `line` asks for, as the shell reads it.
    fn help_of(line: &str) -> Option<&'static Help> {
        let line = wide(line);
        requested(&line, &parse(&line))
    }

    fn names(help: Option<&Help>) -> Option<&'static [&'static str]> {
        help.map(|help| help.names)
    }

    /// The built-in commands the shell runs today.
    const BUILT_INS: [&str; 13] = [
        "call", "cd", "chdir", "cls", "echo", "exit", "path", "prompt", "rem", "set", "shift",
        "type", "ver",
    ];

    #[test]
    fn every_built_in_has_help() {
        for name in BUILT_INS {
            let help = help_of(&format!("{name} /?"));
            assert!(
                help.is_some_and(|help| help.names.contains(&name)),
                "{name} has no help"
            );
        }
    }

    #[test]
    fn help_shows_for_a_command_the_shell_runs_as_a_built_in() {
        // A name in the table the shell does not run as a built-in is still a program's.
        for help in HELP {
            for name in help.names {
                let line = wide(&format!("{name} /?"));
                let command = parse(&line);
                let built_in = !matches!(command, Command::Run { .. });
                assert_eq!(requested(&line, &command).is_some(), built_in, "{name}");
            }
        }
    }

    #[test]
    fn names_are_lowercase_and_each_in_one_entry() {
        let mut seen = Vec::new();
        for help in HELP.iter().chain([&CMD]) {
            for name in help.names {
                assert_eq!(*name, name.to_ascii_lowercase());
                assert!(!seen.contains(name), "{name} twice");
                seen.push(name);
            }
        }
    }

    #[test]
    fn each_syntax_line_starts_with_the_command_s_name() {
        for help in HELP.iter().chain([&CMD]) {
            assert!(!help.syntax.is_empty(), "{:?}", help.names);
            assert!(!help.syntax[0].starts_with(' '), "{:?}", help.names);
            for line in help.syntax.iter().filter(|line| !line.starts_with(' ')) {
                let named = help.names.iter().any(|name| {
                    let upper = name.to_ascii_uppercase();
                    line.strip_prefix(upper.as_str())
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '.']))
                });
                assert!(
                    named,
                    "{line:?} does not start with one of {:?}",
                    help.names
                );
            }
        }
    }

    #[test]
    fn lines_are_ascii_end_with_cr_lf_and_fit_79_columns() {
        for help in HELP.iter().chain([&CMD]) {
            let text = help.to_string();
            assert!(text.is_ascii(), "{:?}", help.names);
            assert!(text.ends_with("\r\n"), "{:?}", help.names);
            let lines: Vec<&str> = text.strip_suffix("\r\n").unwrap().split("\r\n").collect();
            for line in &lines {
                assert!(!line.contains(['\r', '\n']), "{line:?}");
                assert!(line.len() <= WIDTH, "{} columns: {line:?}", line.len());
                assert_eq!(*line, line.trim_end(), "trailing blanks: {line:?}");
            }
        }
    }

    #[test]
    fn the_layout_is_summary_syntax_parameters_notes() {
        let text = of(&wide("cd")).unwrap().to_string();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            lines,
            [
                "Shows the current directory, or changes it.",
                "",
                "CHDIR [/D] [drive:][path]",
                "CHDIR ..",
                "CD [/D] [drive:][path]",
                "CD ..",
                "",
                "  /D    Changes the current drive too, as changing the directory does.",
                "  path  The directory to change to, taken as typed: blanks are part of it, and",
                "        quotes are not removed.",
                "  ..    The parent of the current directory.",
                "",
                "CD alone prints the current directory. When the directory cannot be changed, CD",
                "says so and sets ERRORLEVEL to 1.",
                "",
            ]
        );
    }

    #[test]
    fn where_slash_question_mark_counts() {
        let echo = Some(&["echo"][..]);
        let cd = Some(&["cd", "chdir"][..]);
        let set = Some(&["set"][..]);
        assert_eq!(names(help_of("echo /?")), echo);
        assert_eq!(names(help_of("  @ ECHO\t/?  \r\n")), echo);
        assert_eq!(names(help_of("rem /?")), Some(&["rem"][..]));
        assert_eq!(names(help_of("Chdir /?")), cd);
        assert_eq!(names(help_of("call /?")), Some(&["call"][..]));
        // Echo's and set's text starting with it, run into more text.
        assert_eq!(names(help_of("echo /?x")), echo);
        assert_eq!(names(help_of("set /?x")), set);
        // Any other built-in's, anywhere among its words, run into more text or after a
        // delimiter; call's own, whatever it calls.
        assert_eq!(names(help_of("cd x /?")), cd);
        assert_eq!(names(help_of("cd /?x")), cd);
        assert_eq!(names(help_of("cd,/?")), cd);
        assert_eq!(names(help_of("type a b;/?")), Some(&["type"][..]));
        assert_eq!(names(help_of("call cd /?")), Some(&["call"][..]));
        // Text: past echo's and set's first word, after echo's dot, inside a word or quotes.
        assert!(help_of("echo x /?").is_none());
        assert!(help_of("echo./?").is_none());
        assert!(help_of("set x /?").is_none());
        assert!(help_of("rem x /?").is_none());
        assert!(help_of("cd x/?").is_none());
        assert!(help_of("cd \"/?\"").is_none());
        assert!(help_of("echo /").is_none());
        // A program reads its own.
        assert!(help_of("pwd /?").is_none());
        assert!(help_of("").is_none());
    }

    #[test]
    fn cmd_s_own_switch() {
        let help = |line: &str| crate::switches::switches(&wide(line)).help;
        assert!(help("cmd /?"));
        assert!(help("cmd /q/?"));
        assert!(help("cmd /? /c echo x"));
        // After /C or /K, it is the string's.
        assert!(!help("cmd /c cd /?"));
        assert!(!help("cmd /k /?"));
        assert!(!help("cmd"));
    }

    #[test]
    fn help_returns_1_and_keeps_the_errorlevel() {
        let lines = [
            ("echo /?", 1),
            ("cd /?", 1),
            ("set /?", 1),
            ("exit /?", 1),
            ("rem /?", 0),
        ];
        for (line, code) in lines {
            let mut state = State {
                errorlevel: 5,
                return_code: 9,
                ..State::default()
            };
            let line = wide(line);
            answered(&parse(&line), &mut state);
            assert_eq!((state.errorlevel, state.return_code), (5, code), "{line:?}");
        }
    }
}
