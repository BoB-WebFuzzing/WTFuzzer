#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char* vulns[] = {"SQLi", "SSRF", "FileUpload", "FileDownload", "FileDeletion"};

typedef struct {
    char* key;
    int value;
} KeyValuePair;

typedef struct {
    KeyValuePair** data;
    size_t size;
} Map;

int findIndex(char* arr[], int n, const char* target) {
    for (int i = 0; i < n; ++i) {
        if (strcmp(arr[i], target) == 0) {
            return i;
        }
    }

    return -1;
}

const char* randomSelection(Map map) {
    srand((unsigned int)time(NULL));
    int totalValue = 0;

    for (int i = 0; i < map.size; ++i) {
        totalValue += map.data[i]->value;
    }

    int randomValue = rand() % totalValue;
    int cumulativeValue = 0;

    printf("%d\n", randomValue);

    for (int i = 0; i < map.size; ++i) {
        cumulativeValue += map.data[i]->value;
    
        if (randomValue < cumulativeValue) {
            return map.data[i]->key;
        }
    }
}

void initializeMap(Map* map, size_t size) {
    map->data = (KeyValuePair**)malloc(size * sizeof(KeyValuePair*));
    map->size = size;

    for (size_t i = 0; i < size; ++i) {
        map->data[i] = NULL;
    }
}

void addToMap(Map* map, const char* key, int value) {
    unsigned int index = findIndex(vulns, map->size, key);
    KeyValuePair* newPair = (KeyValuePair*)malloc(sizeof(KeyValuePair));

    newPair->key = strdup(key);
    newPair->value = value;
    map->data[index] = newPair;
}

int getFromMap(const Map* map, const char* key) {
    unsigned int index = findIndex(vulns, map->size, key);
    KeyValuePair* pair = map->data[index];

    if (pair && strcmp(pair->key, key) == 0) {
        return pair->value;
    }

    return -1;
}

void freeMap(Map* map) {
    for (size_t i = 0; i < map->size; ++i) {
        KeyValuePair* pair = map->data[i];

        if (pair) {
            free(pair->key);
            free(pair);
        }
    }

    free(map->data);
}

void main() {
    Map vulnsMap;
    size_t mapSize = 5;
    initializeMap(&vulnsMap, mapSize);

    FILE *fp;
    fp = fopen("/tmp/mutate.txt", "r");
    char line[100];
    char vuln[20];
    int count;
    int i = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("%s", line);
        sscanf(line, "%s : %d", vuln, &count);

        addToMap(&vulnsMap, vuln, count);

        printf("key : %s, value : %d\n------------\n", vuln, getFromMap(&vulnsMap, vuln));
        i++;
    }

    printf("selected vuln : %s\n", randomSelection(vulnsMap));

    fclose(fp);
    freeMap(&vulnsMap);
}
