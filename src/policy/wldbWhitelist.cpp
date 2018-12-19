#include "wldbWhitelist.hpp"

wldbWhitelist* wldbWhitelist::_instance = nullptr;

wldbWhitelist* wldbWhitelist::getInstance(){
		  if(_instance == nullptr){
    _instance =  new wldbWhitelist();
  }
  return _instance;
}

wldbWhitelist::wldbWhitelist():wldbCollection("whitelist"){
	;
}
  
wldbWhitelist::~wldbWhitelist(){
  delete _instance;
}