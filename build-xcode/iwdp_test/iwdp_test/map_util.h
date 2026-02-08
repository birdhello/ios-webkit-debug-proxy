#pragma once

#include <stdbool.h>
#include <inttypes.h>

typedef struct Map Map;

typedef struct MapNode MapNode;

typedef struct MapKey MapKey;

// Create keys
MapKey *map_create_key_by_int(uint64_t key);
MapKey *map_create_key_by_str(const char *key);

Map *map_create(void);

void map_delete(Map *map);

bool map_remove(Map *map, MapKey *key);

void *map_get(Map *map, MapKey *key);

MapNode *map_set(Map *map, MapKey *key, void *value);

MapNode *map_find(Map *map, MapKey *key);

bool map_node_valid(Map *map, MapNode *node);

bool map_node_remove(Map *map, MapNode *node);

void map_node_modify(MapNode *node, void *value);

void *map_node_get(MapNode *node);
