/* getoptions Copyright (c) 2025 Adrian Lopez

   This software is provided 'as-is', without any express or implied warranty.
   In no event will the authors be held liable for any damages arising from the
   use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
      claim that you wrote the original software. If you use this software in a
      product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original software.

   3. This notice may not be removed or altered from any source distribution.
*/

#include "getoptions.h"
#include <stdio.h>
#include <string.h>

int shortarg(char *text, char **argument) {
    if (text[1] != '\0') {
        *argument = text + 1;
    }

    return text[0];
}

int isshortoption(char *text) {
    return text[0] == '-' && text[1] != '-' && text[1] != '\0';
}

int islongoption(char *text) {
    return text[0] == '-' && text[1] == '-' && text[2] != '\0';
}

int isoption(char *text) {
    return islongoption(text) || isshortoption(text);
}

int findmatch(struct getoptions_option *optlist, char *text, char **argument) {
    int x = 0;

    while (optlist[x].value != 0) {
        if (islongoption(text)) {
            if (strstr(&text[2], optlist[x].longidentifier) == &text[2]) {
                const int last = strlen(optlist[x].longidentifier);
                char *const separator = strchr(&text[2], '=');

                if (separator) {
                    if (text[last + 2] == '=') {
                        *argument = separator + 1;
                        break;
                    }
                } else {
                    if (text[last + 2] == '\0') {
                        *argument = 0;
                        break;
                    }
                }
            }
        } else if (isshortoption(text)) {
            if (text[1] == optlist[x].shortidentifier) {
                if (text[2] != '\0') {
                    *argument = &text[2];
                    break;
                } else {
                    *argument = 0;
                    break;
                }
            }
        }

        ++x;
    }

    return x;
}

int getoptions(int argc, char *argv[], struct getoptions_option *optlist, char **argument, int *optindex) {
    int x = *optindex + 1;

    if (x < argc) {
        if (isoption(argv[x])) {
            int islong = islongoption(argv[x]);

            if (argv[x][1] == '\0' || (islong && argv[x][2] == '\0')) {
                *argument = argv[x];

                ++*optindex;

                return GETOPTIONS_NONOPT;
            }

            char *argvalue = 0;

            int match = findmatch(optlist, argv[x], &argvalue);

            if (optlist[match].value == GETOPTIONS_END) {
                // invalid option
                if (islong)
                    fprintf(stderr, "%s: unrecognized option '%s'\n", argv[0], argv[x]);
                else
                    fprintf(stderr, "%s: unrecognized option '-%c'\n", argv[0], argv[x][1]);

                *argument = 0;

                return GETOPTIONS_ERROR;
            }

            if (argvalue) {
                // argument given, check if wanted
                if (optlist[match].wants_arg) {
                    *argument = argvalue;

                    ++*optindex;

                    return optlist[match].value;
                } else {
                    if (islong)
                        fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n", argv[0], optlist[match].longidentifier);
                    else
                        fprintf(stderr, "%s: option '-%c' doesn't allow an argument\n", argv[0], optlist[match].shortidentifier);

                    *argument = 0;

                    return GETOPTIONS_ERROR;
                }
            } else {
                // no argument given, check if required
                if (optlist[match].wants_arg == 1) {
                    if (x + 1 < argc) {
                        *argument = argv[x + 1];

                        *optindex += 2;

                        return optlist[match].value;
                    } else {
                        if (islong)
                            fprintf(stderr, "%s: missing argument for option '--%s'\n", argv[0], optlist[match].longidentifier);
                        else
                            fprintf(stderr, "%s: missing argument for option '-%c'\n", argv[0], optlist[match].shortidentifier);

                        *argument = 0;

                        return GETOPTIONS_ERROR;
                    }
                } else {
                    *argument = 0;

                    ++*optindex;

                    return optlist[match].value;
                }
            }
        } else {
            // non-option argument
            *argument = argv[x];

            ++*optindex;

            return GETOPTIONS_NONOPT;
        }
    }

    return GETOPTIONS_END;
}