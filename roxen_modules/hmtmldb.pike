inherit "roxen-module://dbtable";

constant module_name = "SyncDB: Test table 1";

void create() {
    schema = SyncDB.Schema(
        SyncDB.Types.Integer("id", SyncDB.Flags.Key(),
                                    SyncDB.Flags.Automatic(),
                                    SyncDB.Flags.Join(([ "two" : "id" ]))),
        SyncDB.Types.String("name"),
        SyncDB.Types.String("email"),
        // two
        SyncDB.Types.String("firstname", SyncDB.Flags.Foreign("two", "firstname")),
        SyncDB.Types.String("lastname", SyncDB.Flags.Foreign("two", "lastname")),
    );
    ::create();
}
