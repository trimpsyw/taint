#ifndef TAINT_CHECK_H
#define TAINT_CHECK_H

#include <vector>
#include <algorithm>

struct range {
	app_pc start, end;//[start, end)

	range(app_pc start, app_pc end) : start(start),end(end) {}

	range(app_pc pc) : start(pc), end(pc+1){}

	bool operator<(const range &range) const {
		return (this->start<range.start) | (this->start==range.start && this->end<range.end);
	}
	bool operator>(const range &range) const {
		return (this->start>range.start) | (this->start==range.start && this->end>range.end);
	}
	bool operator==(const range &range) const {
		return (this->start>=range.start && this->end<=range.end);
	}

};

template<class T>
inline bool is_between(const T &low, const T &value, const T &high) {
	return (low<=value && value<high);
}

template<class T>
inline bool is_between(const T &low, const T &value_low, const T &value_high, const T &high) {
	return (low<=value_low && value_high<=high);
}

class merge_pred {
private:
	bool aggressive;

	inline static bool is_adjacent(const range &left, const range &right) {
		return (left.end==right.start);
	}

	inline static bool is_semiadjacent(const range &left, const range &right) {
		return (left.end==right.start-2);
	}

public:
	merge_pred(bool a) : aggressive(a) {}

	bool operator()(range &left, const range &right) const {
		if(
			is_between(left.start, right.start, left.end)
			|| is_adjacent(left, right)
		) {
			left.start=min(left.start, right.start);
			left.end=max(left.end, right.end);
			return true;
		}
		else return false;
	}
};

class memory_list {
public:
	typedef range range_type;
	typedef std::vector<range_type> list_type;
	typedef list_type::size_type size_type;
	typedef list_type::iterator iterator;
	typedef list_type::const_iterator const_iterator;

private:
	list_type _ranges;

	iterator within(app_pc pc, iterator* which = NULL){
		iterator p = _ranges.begin();
		iterator m = _ranges.end();
		int num = _ranges.size();
		app_pc s1, s2;

		while(num > 0)
		{
			m = p + (num >> 1);
			s1 = m->start;
			s2 = m->end;

			if(s1 <= pc && pc < s2)
				return m;

			if(s1 > pc)		num >>= 1;
			else			{p = m+1, num = (num-1) >> 1;}
		}

		if(which) *which = p;
		return _ranges.end();
	}

	const_iterator within(app_pc pc, const_iterator* which = NULL)const{
		const_iterator p = _ranges.begin();
		const_iterator m = _ranges.end();
		int num = _ranges.size();
		app_pc s1, s2;

		while(num > 0)
		{
			m = p + (num >> 1);
			s1 = m->start;
			s2 = m->end;

			if(s1 <= pc && pc < s2)
				return m;

			if(s1 > pc)		num >>= 1;
			else			{p = m+1, num = (num-1) >> 1;}
		}

		if(which) *which = p;
		return _ranges.end();
	}

public:
	void insert(const range &r){
		const_iterator which;
		const_iterator it = within(r.start, &which);
		
		if(it == _ranges.end())
			_ranges.insert(which, r);
		else
			_ranges.insert(++it, r);

		iterator here = std::unique(_ranges.begin(), _ranges.end(), merge_pred(true));
		_ranges.erase(here, _ranges.end());
	}

	void optimize(bool aggressive=false){
		std::sort(_ranges.begin(), _ranges.end());
		iterator end = std::unique(_ranges.begin(), _ranges.end(), merge_pred(aggressive));
		if(end != _ranges.end())
			_ranges.erase(end, _ranges.end());
	}

	bool remove(app_pc start, app_pc end){
		if(start > end)
			return false;

		iterator it1, it2;
		if(within(start, &it1)==_ranges.end() && 
			within(end, &it2)==_ranges.end() && 
			it1 == it2)
			return false;
		
		insert(range(start, end));

		iterator it = within(start);
		if(it != _ranges.end()){
			if(it->start == start){
				if(it->end == end) _ranges.erase(it);
				else it->start = end;//[0,100)-[0,11)=[11,100)
			}
			else if(it->end == end)//[0,100)-[11,100)=[0,11)
				it->end = start;
			else{//[0,100)-[11,90)=[0,11)+[90,100) 
				app_pc old_end = it->end;
				it->end = start;
				_ranges.insert(++it, range(end, old_end));
			}
		}
		return true;
	}

	bool find(app_pc pc){
		if(_ranges.size() == 0) return false;
		return within(pc) != _ranges.end();
	}

	iterator at(app_pc pc){
		return within(pc);
	}
	
	iterator begin() {
		return this->_ranges.begin();
	}
	iterator end() {
		return this->_ranges.end();
	}

	const_iterator begin() const {
		return this->_ranges.begin();
	}
	const_iterator end() const {
		return this->_ranges.end();
	}

	size_type size() const {
		return this->_ranges.size();
	}
	void clear() {
		this->_ranges.clear();
	}

	memory_list() {}
};

#endif