#include "map_util.h"

#include <stdlib.h>
#include <string.h>

// 升序：小 -> 大
typedef enum {
    MAP_KEY_INT = 0,
    MAP_KEY_STR = 1
} MapKeyType;

struct MapKey {
    MapKeyType type;
    union {
        uint64_t i;
        char *s; // owned, heap-allocated copy
    } u;
};

static int map_key_cmp(const MapKey *a, const MapKey *b) {
    if (a->type != b->type) {
        // Order by type to ensure deterministic ordering: INT < STR
        return (int)a->type - (int)b->type;
    }
    if (a->type == MAP_KEY_INT) {
        if (a->u.i == b->u.i) return 0;
        return a->u.i < b->u.i ? -1 : 1;
    } else {
        // Both strings; handle NULLs defensively
        const char *as = a->u.s ? a->u.s : "";
        const char *bs = b->u.s ? b->u.s : "";
        int c = strcmp(as, bs);
        if (c < 0) return -1;
        if (c > 0) return 1;
        return 0;
    }
}

static void map_key_free_(MapKey *k) {
    if (!k) return;
    if (k->type == MAP_KEY_STR) {
        free(k->u.s);
    }
    free(k);
}

struct MapNode {
    MapKey *key;
    void *value;
    MapNode *before;
    MapNode *next;
};

struct Map {
    MapNode *node;
};

Map *map_create(void) {
    return calloc(1, sizeof(Map));
}

void map_delete(Map *map) {
    MapNode *node = map->node;
    while (node) {
        if (node->next) {
            node = node->next;
            // free previous node and its key
            map_key_free_(node->before->key);
            free(node->before);
        } else {
            map_key_free_(node->key);
            free(node);
            break;
        }
    }
    free(map);
}

bool map_remove(Map *map, MapKey *key) {
    MapNode *beforeNode = 0;
    MapNode *currentNode = map->node;
    while(currentNode) {
        int cmp = map_key_cmp(key, currentNode->key);
        if (cmp == 0) {
            if (beforeNode) {
                beforeNode->next = currentNode->next;
                if (currentNode->next) {
                    currentNode->next->before = beforeNode;
                }
            } else {
                map->node = currentNode->next;
                if (map->node) {
                    map->node->before = NULL;
                }
            }
            map_key_free_(currentNode->key);
            free(currentNode);
            return true;
        } else if (cmp < 0) {
            return false;
        } else { // cmp > 0
            beforeNode = currentNode;
            currentNode = beforeNode->next;
        }
    }
    return false;
}

void *map_get(Map *map, MapKey *key) {
    MapNode *currentNode = map->node;
    while(currentNode) {
        int cmp = map_key_cmp(key, currentNode->key);
        if (cmp == 0) {
            return currentNode->value;
        } else if (cmp < 0) {
            return NULL;
        } else { // cmp > 0
            currentNode = currentNode->next;
        }
    }
    return NULL;
}

MapNode *map_set(Map *map, MapKey *key, void *value) {
    MapNode *beforeNode = 0;
    MapNode *currentNode = map->node;
    if (currentNode) {
        do {
            int cmp = map_key_cmp(key, currentNode->key);
            if (cmp == 0) {
                return NULL;
            } else if (cmp < 0) {
                MapNode* new_node = calloc(1, sizeof(MapNode));
                if (!new_node) {
                    return NULL;
                }
                new_node->key = key;
                if (key->type == MAP_KEY_STR) {
                    new_node->key->u.s = strdup(key->u.s);
                }
                new_node->value = value;
                new_node->next = currentNode;
                currentNode->before = new_node;

                if (beforeNode) {
                    beforeNode->next = new_node;
                    new_node->before = beforeNode;
                } else {
                    new_node->before = NULL;
                    map->node = new_node;
                }
                return new_node;
            } else { // cmp > 0
                beforeNode = currentNode;
                currentNode = beforeNode->next;
            }
        } while(currentNode);

        MapNode* new_node = calloc(1, sizeof(MapNode));
        if (!new_node) {
            return NULL;
        }
        beforeNode->next = new_node;
        new_node->before = beforeNode;
        new_node->key = key;
        new_node->value = value;
        new_node->next = NULL;
        return new_node;
    } else {
        map->node = calloc(1, sizeof(MapNode));
        if (!map->node) {
            return NULL;
        }
        map->node->key = key;
        if (key->type == MAP_KEY_STR) {
            map->node->key->u.s = strdup(key->u.s);
        }
        map->node->value = value;
        map->node->next = NULL;
        map->node->before = NULL;
        return map->node;
    }
}

MapNode *map_find(Map *map, MapKey *key) {
    MapNode *currentNode = map->node;
    while(currentNode) {
        int cmp = map_key_cmp(key, currentNode->key);
        if (cmp == 0) {
            return currentNode;
        } else if (cmp < 0) {
            return NULL;
        } else { // cmp > 0
            currentNode = currentNode->next;
        }
    }
    return NULL;
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
    return false;
}

bool map_node_remove(Map *map, MapNode *node) {
    if (node->next) {
        if (node->before) {
            node->before->next = node->next;
            node->next->before = node->before;
            map_key_free_(node->key);
            free(node);
            return true;
        } else {
            map->node = node->next;
            map->node->before = NULL;
            map_key_free_(node->key);
            free(node);
            return true;
        }
    } else {
        if (node->before) {
            node->before->next = NULL;
            map_key_free_(node->key);
            free(node);
            return true;
        } else {
            map->node = NULL;
            map_key_free_(node->key);
            free(node);
            return true;
        }
    }
}

void map_node_modify(MapNode *node, void *value) {
    node->value = value;
}

void *map_node_get(MapNode *node) {
    return node->value;
}

MapKey *map_create_key_by_int(uint64_t key) {
    MapKey *k = (MapKey *)calloc(1, sizeof(MapKey));
    if (!k) return NULL;
    k->type = MAP_KEY_INT;
    k->u.i = key;
    return k;
}

MapKey *map_create_key_by_str(const char *key) {
    MapKey *k = (MapKey *)calloc(1, sizeof(MapKey));
    if (!k) return NULL;
    k->type = MAP_KEY_STR;
    k->u.s = key;
    return k;
}
