//
//  csv.h
//
//  Created by Pietro Saccardi on 05/12/15.
//  http://stackoverflow.com/questions/1120140/how-can-i-read-and-parse-csv-files-in-c
//
//  This work is licensed under the Creative Commons Attribution-ShareAlike 3.0 Unported License.
//  To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/3.0/ or send
//  a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
//

// changed to add reading hex from file as numbers

#ifndef csv_h
#define csv_h

#include <iterator>
#include <sstream>
#include <string>

namespace csvtools {
    /// Read the last element of the tuple without calling recursively
    template <std::size_t idx, class... fields>
    typename std::enable_if<idx >= std::tuple_size<std::tuple<fields...>>::value - 1>::type
    read_tuple(std::istream &in, std::tuple<fields...> &out, const char delimiter) {
        std::string cell;
        std::getline(in, cell, delimiter);
        std::stringstream cell_stream(cell);
        cell_stream.setf(std::ios::hex, std::ios::basefield);
        cell_stream >> std::get<idx>(out);
    }

    /// Read the @p idx-th element of the tuple and then calls itself with @p idx + 1 to
    /// read the next element of the tuple. Automatically falls in the previous case when
    /// reaches the last element of the tuple thanks to enable_if
    template <std::size_t idx, class... fields>
    typename std::enable_if<idx < std::tuple_size<std::tuple<fields...>>::value - 1>::type
    read_tuple(std::istream &in, std::tuple<fields...> &out, const char delimiter) {
        std::string cell;
        std::getline(in, cell, delimiter);
        std::stringstream cell_stream(cell);
        cell_stream.setf(std::ios::hex, std::ios::basefield);
        cell_stream >> std::get<idx>(out);
        read_tuple<idx + 1, fields...>(in, out, delimiter);
    }
}

/// Iterable csv wrapper around a stream. @p fields the list of types that form up a row.
template <class... fields>
class csv {
    std::istream &_in;
    const char _delim;
public:
    typedef std::tuple<fields...> value_type;
    class iterator;

    /// Construct from a stream.
    inline csv(std::istream &in, const char delim) : _in(in), _delim(delim) {}

    /// Status of the underlying stream
    /// @{
    inline bool good() const {
        return _in.good();
    }
    inline const std::istream &underlying_stream() const {
        return _in;
    }
    /// @}

    inline iterator begin();
    inline iterator end();
private:

    /// Reads a line into a stringstream, and then reads the line into a tuple, that is returned
    inline value_type read_row() {
        std::string line;
        std::getline(_in, line);
        std::stringstream line_stream(line);
        std::tuple<fields...> retval;
        csvtools::read_tuple<0, fields...>(line_stream, retval, _delim);
        return retval;
    }
};

/// Iterator; just calls recursively @ref csv::read_row and stores the result.
template <class... fields>
class csv<fields...>::iterator {
    typename csv::value_type _row;
    csv *_parent;
public:
    typedef std::input_iterator_tag    iterator_category;
    typedef typename csv::value_type   value_type;
    typedef std::size_t                difference_type;
    typedef typename csv::value_type * pointer;
    typedef typename csv::value_type & reference;

    /// Construct an empty/end iterator
    inline iterator() : _parent(nullptr) {}
    /// Construct an iterator at the beginning of the @p parent csv object.
    inline iterator(csv &parent) : _parent(parent.good() ? &parent : nullptr) {
        ++(*this);
    }

    /// Read one row, if possible. Set to end if parent is not good anymore.
    inline iterator &operator++() {
        if (_parent != nullptr) {
            _row = _parent->read_row();
            if (!_parent->good()) {
                _parent = nullptr;
            }
        }
        return *this;
    }

    inline iterator operator++(int) {
        iterator copy = *this;
        ++(*this);
        return copy;
    }

    inline typename csv::value_type const &operator*() const {
        return _row;
    }

    inline typename csv::value_type const *operator->() const {
        return &_row;
    }

    bool operator==(iterator const &other) {
        return (this == &other) || (_parent == nullptr && other._parent == nullptr);
    }
    bool operator!=(iterator const &other) {
        return !(*this == other);
    }
};

template <class... fields>
typename csv<fields...>::iterator csv<fields...>::begin() {
    return iterator(*this);
}

template <class... fields>
typename csv<fields...>::iterator csv<fields...>::end() {
    return iterator();
}

#endif /* csv_h */
