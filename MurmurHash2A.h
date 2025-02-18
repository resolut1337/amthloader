#ifndef MURMURHASH_H
#define MURMURHASH_H

/*
 * MurmurHash2A - ��������� ����������� �� ��������� MurmurHash2A (https://ru.wikipedia.org/wiki/MurmurHash2)
 * ���������:
 * const void *key - ��������� �� �����, ������� ����� ����������.
 * int len - ����� ������.
 * unsigned int seed - ��������� �������� ��� �������������
*/

unsigned int MurmurHash2A(const void* key, int len, unsigned int seed);

#endif //MURMURHASH_H
