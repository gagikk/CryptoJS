#include <emscripten/bind.h>
#include <string>
#include <vector>

using namespace emscripten;


struct Person
{
    std::string name ;
    int age;
};

std::vector<Person> procreate (const Person & p, int n) {
    std::vector<Person> v(n, p);
    return v;
}

std::vector<Person> append (std::vector<Person> &v, const Person &p ) {
    std::vector<Person> _v(v);
    _v.push_back(p);
    return _v;
}
//std::map<int, std::string> returnMapData () {
//    std::map<int, std::string> m;
//    m.insert(std::pair<int, std::string>(10, "This is a string."));
//    return m;
//}

EMSCRIPTEN_BINDINGS(module) {
    function("procreate", &procreate);
    function("append", &append);
    value_object<Person>("Person")
        .field("name", &Person::name)
        .field("age", &Person::age);
    // register bindings for std::vector<int> and std::map<int, std::string>.
    register_vector<Person>("vector<Person>");
    register_map<int, std::string>("map<int, string>");
}
