#ifndef GETOPTIONS_H
#define GETOPTIONS_H

#define GETOPTIONS_END    0
#define GETOPTIONS_ERROR  -1
#define GETOPTIONS_NONOPT -2

struct getoptions_option {
    char *longidentifier;
    char shortidentifier;
    int wants_arg;
    int value;
};

int getoptions(int argc, char *argv[], struct getoptions_option *optlist, char **argument, int *optindex);

#endif