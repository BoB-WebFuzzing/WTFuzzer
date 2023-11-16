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

char* insertString(const char* original, const char* insertion, size_t position) {
    size_t originalLen = strlen(original);
    size_t insertionLen = strlen(insertion);

    char* result = (char*)malloc(originalLen + insertionLen + 1);
    if (result == NULL)
        exit(EXIT_FAILURE);

    memcpy(result, original, position);
    memcpy(result + position, insertion, insertionLen);
    memcpy(result + position + insertionLen, original + position, originalLen - position + 1);

    return result;
}

void mutateSQLI(char* value) {
    int targetIndex = rand() % strlen(value);
    char* mutateSet[8] = {"\'", "\"", "\\", "#", "-- -", "--%20-", "%23", ""};
    strcpy(value, insertString(value, mutateSet[rand() % 8], targetIndex));
}

void mutateSSRF(char* value) {
    int targetIndex = rand() % strlen(value);
    char* mutateSet[3] = {"http://localhost", "http://127.0.0.1", "file:///etc/passwd"};
    // strcpy(value, insertString(value, mutateSet[rand() % 3], targetIndex));
    strcpy(value, mutateSet[rand() % 3]);
}

void mutateFILE(char* value) {
    int targetIndex = rand() % strlen(value);
    char* mutateSet[4] = {"/", "/../../../etc/passwd", "/etc/passwd", "/\\../\\../\\..\\/etc/passwd"};
    // strcpy(value, insertString(value, mutateSet[rand() % 4], targetIndex));
    strcpy(value, mutateSet[rand() % 4]);
}

void mutate(char* ret, const char* vuln, char* seed, int length);

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
    const char* svuln = randomSelection(vulnsMap);

    //------------ mutate
    char mutetdSeed[1000];
    char buffer[10000];
    FILE *mu;
    mu = fopen("mutest", "r");
    int bufsize = fread(buffer, 1, (1 * 1024 * 1024), mu);
    fclose(mu);



    mutate(mutetdSeed, svuln, buffer, bufsize);

    for (int i = 0; i < bufsize+30; i++) {
        printf("%c", mutetdSeed[i]);
    }
    printf("\n");

    //------------

    fclose(fp);
    freeMap(&vulnsMap);
}

void mutate(char* ret, const char* vuln, char* seed, int length) {
    char* get = NULL;
    char* post = NULL;
    char buffer[10000];
    int part = 0;
    int i = 0;

    seed += 1;

    while (i < length) {
        if (seed[i] == '\x00') {
            strncpy(buffer, seed, i);

            buffer[i] = '\0';

            switch (part) {
                case 0:
                    get = strdup(buffer);
                    break;
                case 1:
                    post = strdup(buffer);
                    break;
                default:
                    break;
            }

            memset(buffer, 0, sizeof(buffer));

            seed += i + 1;
            length -= i + 1;
            i = 0;
            part++;

            continue;
        }

        i++;
    }

    char* getArray[10];
    int getCount = 0;
    char* getKey[10];
    char* getValue[10];

    char* postArray[10];
    int postCount = 0;
    char* postKey[10];
    char* postValue[10];

// Parsing by &
    if (strcmp(get, "")) {
        char* getToken = strdup(strtok(get, "&"));
        char* tempToken;
        i = 0;

        while (getToken != NULL && i < 10) {
            getArray[i] = getToken;
            i++;
            getCount++;

            // free(getToken);
            tempToken = strtok(NULL, "&");

            if (tempToken == NULL)
                break;

            getToken = strdup(tempToken);
        }
    }

    if (strcmp(post, "")) {
        char* postToken = strdup(strtok(post, "&"));
        char* tempToken;
        i = 0;

        while (postToken != NULL && i < 10) {
            postArray[i] = postToken;
            i++;
            postCount++;

            // free(postToken);
            tempToken = strtok(NULL, "&");

            if (tempToken == NULL)
                break;

            postToken = strdup(tempToken);
        }
    }

// Parsing by =
    for (int i = 0; i < getCount; i++) {
        if (getArray[i]) {
            getKey[i] = strdup(strtok(getArray[i], "="));
            getValue[i] = strdup(strtok(NULL, "="));
        }
    }

    for (int i = 0; i < postCount; i++) {
        if (postArray[i]) {
            postKey[i] = strdup(strtok(postArray[i], "="));
            postValue[i] = strdup(strtok(NULL, "="));
        }
    }

// Select vuln class
    switch (findIndex(vulns, 5, vuln)) {
        case 0:
            printf("vuln is %s\n", vuln);

            if (getCount) {
                for (int i = 0; i < getCount; i++) {
                    mutateSQLI(getValue[i]);
                }
            }
            if (postCount) {
                for (int i = 0; i < postCount; i++) {
                    mutateSQLI(postValue[i]);
                }
            }

            break;
        case 1:
            printf("vuln is %s\n", vuln);

            if (getCount) {
                for (int i = 0; i < getCount; i++) {
                    mutateSSRF(getValue[i]);
                }
            }
            if (postCount) {
                for (int i = 0; i < postCount; i++) {
                    mutateSSRF(postValue[i]);
                }
            }

            break;
        case 2:
            printf("vuln is %s\n", vuln);

            if (getCount) {
                for (int i = 0; i < getCount; i++) {
                    mutateFILE(getValue[i]);
                }
            }
            if (postCount) {
                for (int i = 0; i < postCount; i++) {
                    mutateFILE(postValue[i]);
                }
            }

            break;
        case 3:
            printf("vuln is %s\n", vuln);

            if (getCount) {
                for (int i = 0; i < getCount; i++) {
                    mutateFILE(getValue[i]);
                }
            }
            if (postCount) {
                for (int i = 0; i < postCount; i++) {
                    mutateFILE(postValue[i]);
                }
            }

            break;
        case 4:
            printf("vuln is %s\n", vuln);

            if (getCount) {
                for (int i = 0; i < getCount; i++) {
                    mutateFILE(getValue[i]);
                }
            }
            if (postCount) {
                for (int i = 0; i < postCount; i++) {
                    mutateFILE(postValue[i]);
                }
            }

            break;
        default:
            printf("%s is not in vulns\n", vuln);
    }

// Concat by =, &
    if (strcmp(get, "")) {
        for (int i = 0; i < getCount; i++) {
            getArray[i] = strcat(strcat(getKey[i], "="), getValue[i]);
        }

        get = getArray[0];

        for (int i = 1; i < getCount; i++) {
            strcat(strcat(get, "&"), getArray[i]);
        }
    }

    if (strcmp(post, "")) {
        for (int i = 0; i < postCount; i++) {
            postArray[i] = strcat(strcat(postKey[i], "="), postValue[i]);
        }

        post = postArray[0];

        for (int i = 1; i < postCount; i++) {
            strcat(strcat(post, "&"), postArray[i]);
        }
    }

    if (strcmp(get, "") && strcmp(post, "")) {
        ret[0] = '\x00';
        strcat(ret + 1, get);
        ret[1 + strlen(get)] = '\x00';
        strcat(ret + 2 + strlen(get), post);
        ret[1 + strlen(get) + 1 + strlen(post)] = '\x00';
    } else if (strcmp(get, "") && !strcmp(post, "")) {
        ret[0] = '\x00';
        strcat(ret + 1, get);
        ret[1 + strlen(get)] = '\x00';
        ret[1 + strlen(get) + 1] = '\x00';
    } else if (!strcmp(get, "") && strcmp(post, "")) {
        ret[0] = '\x00';
        ret[1] = '\x00';
        strcat(ret + 2, post);
        ret[2 + strlen(post)] = '\x00';
    } else {
        ret[0] = '\x00';
        ret[1] = '\x00';
        ret[2] = '\x00';
    }

    if (strcmp(get, "")) {
        printf("get : %s\n", get);
        free(get);
    }

    if (strcmp(post, "")) {
        printf("post : %s\n", post);
        free(post);
    }
}
