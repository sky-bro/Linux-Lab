#include <iostream>
#include <memory>

using namespace std;

template <typename T>
class my_shared_ptr {
private:
    T* _ptr;
    int *cnt;
public:
    my_shared_ptr(): _ptr(nullptr), cnt(nullptr) {}
    my_shared_ptr(T* p): _ptr(p), cnt(nullptr) {
        if (p) cnt = new int(1);
    }
    my_shared_ptr(const my_shared_ptr<T> &rhs): _ptr(rhs._ptr), cnt(rhs.cnt) {
        if (_ptr) ++*rhs.cnt;
    }
    ~my_shared_ptr() {
        if (_ptr && 0 == --*cnt) {
            delete cnt;
            delete _ptr;
        }
    }
    my_shared_ptr<T>& operator=(const my_shared_ptr<T> &rhs) {
        if (&rhs != this) {
            if (this->_ptr && 0 == --*this->cnt) {
                delete cnt;
                delete _ptr;
            }
            this->_ptr = rhs._ptr;
            this->cnt = rhs.cnt;
            if (rhs._ptr) {
                ++*rhs.cnt;
            }
        }
        return *this;
    }
    T* get() const { return _ptr; }
    int use_count() { return cnt ? *cnt : 0; }
};

template <typename T>
ostream& operator<<(ostream &os, const my_shared_ptr<T> &p) {
    return os << p.get();
}

int main(int argc, char const *argv[])
{
    my_shared_ptr<const int> p(nullptr);
    my_shared_ptr<const int> p2(new int(3));
    my_shared_ptr<const int> p3(p);
    my_shared_ptr<const int> p4(p2);
    cout << "p2: " << p2 << endl;
    cout << "p4: " << p4 << endl;
    cout << p4.use_count() << endl;
    return 0;
}
