#include "map_util.h"

#include <stdlib.h>

// 小 -> 大
struct MapNode {
    int key;
    void *value;
    void *before;
    void *next;
};

struct Map {
    MapNode *node;
};

Map *map_create(void) {
    Map *map = malloc(sizeof(Map));
    map->node = 0;
    return map;
}

void map_delete(Map *map) {
    MapNode *node = map->node;
    while (node) {
        if (node->next) {
            node = node->next;
            free(node->before);
        } else {
            free(node);
            break;
        }
    }
    free(map);
}

bool map_remove(Map *map, int key) {
    MapNode *beforeNode = 0;
    MapNode *currentNode = map->node;
    while(currentNode) {
        if (key == currentNode->key) {
            if (beforeNode) {
                beforeNode->next = currentNode->next;
                ((MapNode *) currentNode->next)->before = beforeNode;
            } else {
                map->node = currentNode->next;
                map->node->before = 0;
            }
            free(currentNode);
            return true;
        } else if (key < currentNode->key) {
            return false;
        } else { // key > currentNode->key
            beforeNode = currentNode;
            currentNode = beforeNode->next;
        }
    }
    return false;
}

void *map_get(Map *map, int key) {
    MapNode *currentNode = map->node;
    while(currentNode) {
        if (key == currentNode->key) {
            return currentNode->value;
        } else if (key < currentNode->key) {
            return 0;
        } else { // key > currentNode->key
            currentNode = currentNode->next;
        }
    }
    return 0;
}

MapNode *map_set(Map *map, int key, void *value) {
    MapNode *beforeNode = 0;
    MapNode *currentNode = map->node;
    if (currentNode) {
        do {
            if (key == currentNode->key) {
                return 0;
            } else if (key < currentNode->key) {
                MapNode* new_node = malloc(sizeof(MapNode));
                new_node->key = key;
                new_node->value = value;
                new_node->next = currentNode;

                if (beforeNode) {
                    new_node->before = beforeNode;
                    beforeNode->next = new_node;
                } else {
                    new_node->before = 0;
                    map->node = new_node;
                }
                return new_node;
            } else { // key > currentNode->key
                beforeNode = currentNode;
                currentNode = beforeNode->next;
            }
        } while(currentNode);

        MapNode* new_node = beforeNode->next = malloc(sizeof(MapNode));
        new_node->before = beforeNode;
        new_node->key = key;
        new_node->value = value;
        new_node->next = 0;
        return new_node;
    } else {
        map->node = malloc(sizeof(MapNode));
        map->node->key = key;
        map->node->value = value;
        map->node->next = 0;
        map->node->before = 0;
        return map->node;
    }
}

MapNode *map_find(Map *map, int key) {
    MapNode *currentNode = map->node;
    while(currentNode) {
        if (key == currentNode->key) {
            return currentNode;
        } else if (key < currentNode->key) {
            return 0;
        } else { // key > currentNode->key
            currentNode = currentNode->next;
        }
    }
    return 0;
}

bool map_node_valid(Map *map, MapNode *node) {
    MapNode *currentNode = map->node;
    while(currentNode) {
        if (currentNode == node) {
            return true;
        } else { // key > currentNode->key
            currentNode = currentNode->next;
        }
    }
    return 0;
}

bool map_node_remove(Map *map, MapNode *node) {
    if (node->next) {
        if (node->before) {
            ((MapNode *) node->before)->next = node->next;
            ((MapNode *) node->next)->before = node->before;
            free(node);
            return true;
        } else {
            map->node = node->next;
            map->node->before = 0;
            free(node);
            return true;
        }
    } else {
        if (node->before) {
            ((MapNode *) node->before)->next = 0;
            free(node);
            return true;
        } else {
            return false;
        }
    }
}

void map_node_modify(MapNode *node, void *value) {
    node->value = value;
}

void *map_node_get(MapNode *node) {
    return node->value;
}
