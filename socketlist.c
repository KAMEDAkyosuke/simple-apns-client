#include "socketlist.h"

#include <stdlib.h>

socketlist_t* socketlist_append(socketlist_t* list, int socket)
{
    socketlist_t* new_item = (socketlist_t*) malloc(sizeof(socketlist_t));
    new_item->next = NULL;
    new_item->socket = socket;
    new_item->is_closed = false;

    if(list == NULL){
        return new_item;
    }
    else{
        socketlist_t* last = list;
        while(last->next != NULL){
            last = last->next;
        }
        last->next = new_item;
        return list;
    }
}

void socketlist_free(socketlist_t* list)
{
    socketlist_t *current = list;
    while(current != NULL){
        socketlist_t* tmp = current;
        current = current->next;
        free(tmp);
        tmp = NULL;
    }
}

socketlist_t* socketlist_delete(socketlist_t* list, socketlist_t* target)
{
    if(list == target){
        socketlist_t* next = list->next;
        free(list);
        return next;
    }

    socketlist_t* tmp = list;
    while(tmp != NULL && tmp->next != target){
        tmp = tmp->next;
    }
    if(tmp == NULL){    /* NOT FOUND */
        return list;
    }

    socketlist_t* next = target->next;
    free(target);
    tmp->next = next;
    return list;
}

socketlist_t* socketlist_delete_closed_socket(socketlist_t* list)
{
    socketlist_t* root = list;
    socketlist_t* p = list;
    while(p != NULL){
        socketlist_t* next = p->next;
        if(p->is_closed){
            root = socketlist_delete(root, p);
        }
        p = next;
    }
    return root;
}
