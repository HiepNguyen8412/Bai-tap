#include <iostream>

using namespace std;

int GlobalVar = 10;

void function()
{
    int LocalVar = 20;
    static int StaticVar = 30;
    int *p = new int(40);

    cout << "Địa chỉ của GlobalVar: " << &GlobalVar << endl;
    cout << "Địa chỉ của LocalVar: " << &LocalVar << endl;
    cout << "Địa chỉ của StaticVar: " << &StaticVar << endl;
    cout << "Địa chỉ của Heap: " << p << endl;

    uintptr_t Address_GlobalVar = reinterpret_cast<uintptr_t>(&GlobalVar);
    uintptr_t Address_LocalVar = reinterpret_cast<uintptr_t>(&LocalVar);
    uintptr_t Address_StaticVar = reinterpret_cast<uintptr_t>(&StaticVar);
    uintptr_t Address_Heap = reinterpret_cast<uintptr_t>(p);

    cout << "KHoảng cách địa chỉ từ GlobalVar <-> Local: " << Address_GlobalVar - Address_LocalVar << endl;
    cout << "Khoảng cách địa chỉ từ StaticVar <-> Heap: " << Address_StaticVar - Address_Heap << endl;
}

int main()
{
    function();
    return 0;
}