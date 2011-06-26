class Sync(void|string id, void|array(int) version, void|array(mapping) rows) {
    string _sprintf(int type) {
	return sprintf("%O(%O, %O)", this_program, id, error);
    }
}
class SyncReq(void|string id, void|array(int) version) {
    string _sprintf(int type) {
	return sprintf("%O(%O, %O)", this_program, id, error);
    }
}
class Error(void|string id, void|string error) { 
    string _sprintf(int type) {
	return sprintf("%O(%O, %O)", this_program, id, error);
    }
}
class Base(void|string id, void|mapping row) { 
    string _sprintf(int type) {
	return sprintf("%O(%O, %O)", this_program, id, row);
    }
}
class Select(void|string id, object filter) {
    string _sprintf(int type) {
	return sprintf("%O(%O, %O)", this_program, id, filter);
    }
}
class Insert { inherit Base; }
class Update { inherit Base; }


