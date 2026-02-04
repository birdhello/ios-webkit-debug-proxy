#pragma once

#include <stdbool.h>

typedef struct Map Map;

typedef struct MapNode MapNode;

Map *map_create(void);

void map_delete(Map *map);

bool map_remove(Map *map, int key);

void *map_get(Map *map, int key);

MapNode *map_set(Map *map, int key, void *value);

MapNode *map_find(Map *map, int key);

bool map_node_valid(Map *map, MapNode *node);

bool map_node_remove(Map *map, MapNode *node);

void map_node_modify(MapNode *node, void *value);
