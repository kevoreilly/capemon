typedef HANDLE CRTHANDLE;

/*
* Structure defs for FindFixAndSave hook in cmd.exe
* From https://github.com/KingKDot/Exorcism/blob/54a44302469160aa7b93f4b72e93206d06a786ac/cmdtest/cmdtest/dllmain.cpp#L70
*/
struct savtype {
	TCHAR* saveptrs[12];
};

struct relem {
	CRTHANDLE rdhndl;       // handle to be redirected
	TCHAR* fname;           // filename (or &n)
	CRTHANDLE svhndl;       // where orig handle is saved
	int flag;               // Append flag
	TCHAR rdop;             // Type ('>' | '<')
	struct relem* nxt;      // Next structure
};

struct node {               // Used for operators
	int type;               // Type of operator
	struct savtype save;    // FOR processor saves orig strings here
	struct relem* rio;      // M022 - Linked redirection list
	struct node* lhs;       // Ptr to left hand side of the operator
	struct node* rhs;       // Ptr to right hand side of the operator
	INT_PTR extra[4];       // M022 - Padding now needed
};

struct cmdnode {
	int type;               // Type of command
	struct savtype save;    // FOR processor saves orig strings here
	struct relem* rio;      // M022 - Linked redirection list
	PTCHAR cmdline;         // Ptr to command line
	PTCHAR argptr;          // Ptr to type of command
	int flag;               // M022 - Valid for cond and goto types
	int cmdarg;             // M022 - Argument to STRTYP routine
};
