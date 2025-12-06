# Introduction

Dirchanges summarizes differences between directories, archives, or lists of
hashes representing the same content at different points in time, producing a
list of files and directories added, modified, or removed.


# Usage

```
Usage: dirchanges [options...] FROM [options...] [TO] [options...]

Summarize differences between FROM and TO, where FROM and TO are directories,
archives, or lists of hashes representing the same content at different points
in time, producing a list of files and directories added, modified, or removed.

 -H --hash              read files in FROM and print a list of hashes to
                        standard output for later use
 -w --within=DIRECTORY  include only files appearing below DIRECTORY; this
                        option applies to the preceding argument (FROM or TO)
                        and, if used, must appear directly after it
 -s --short             tag files added, removed or modified with +, -, ~
                        instead of Added, Removed, and Modified
 -v --verbose           verbosely list the files being processed
 -V --version           print version number
 -h --help              display this help message
```


# Examples

To keep track of changes to a directory over time you may create a list of hashes from
the contents of that directory and save them to a file:

  `$ dirchanges --hash directory > directory.hashes`

You may then obtain a list of changes as follows:

  `$ dirchanges directory.hashes directory`

Another use case is to compare a directory against a backup of it:

  `$ dirchanges directory-backup.tar directory`

For directories deeper down the archive's root, the --within option may prove useful:

  `$ dirchanges directory-backup.tar --within=home/user/directory directory`

You may also compare directories across different media:

  `$ dirchanges directory /media/USB\ Drive/directory`


# Contact Information for Adrian Lopez

email: adrianlopezroche@gmail.com