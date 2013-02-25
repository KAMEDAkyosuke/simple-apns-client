#ifndef INTLIST_H
#define INTLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

typedef struct socketlist{
    struct socketlist* next;
    int socket;
    bool is_closed;
} socketlist_t;

socketlist_t* socketlist_append(socketlist_t* list, int socket);
void socketlist_free(socketlist_t* list);
socketlist_t* socketlist_delete(socketlist_t* list, socketlist_t* target);
socketlist_t* socketlist_delete_closed_socket(socketlist_t* list);

#ifdef __cplusplus
}
#endif

#endif
