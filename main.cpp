/*
	A program that takes arguments (path),(privilege level) in order to run a program at the users desired level of privilege without having to
	have administrator privileges on the given account I.E, standard user.
*/

#include <iostream>
#include <windows.h>
#include "init.h"

int main()
{
	init sd;
	sd.setSecurityDescriptor();
	std::cout << "init sec descriptor error: " << GetLastError() << "\n"; // debug statement
	SECURITY_DESCRIPTOR x = sd.getSecurityDescriptor();

	SECURITY_ATTRIBUTES procAttribs // this gets passed as a pointer to this struct as an argument to CreateProcessA() function.
	{
		sizeof(SECURITY_ATTRIBUTES),
		&x, // pointer to the SECURITY_DESCRIPTOR struct.
		FALSE // tells us whether the security_attributes is inheritable.
	};

	STARTUPINFOA sInfo{ 0 }; // startup structure initialized to 0 to pass to CreateProcessA() (default)
	PROCESS_INFORMATION pInfo{ 0 }; // proc info initialized to 0 to pass it to the CreateProcessA() structure (default)

	// function to create the higher level process. 
	BOOL mainProc = CreateProcessA(
		NULL,
		(LPSTR)"C:\\Windows\\System32\\cmd.exe", // path to application to be run
		&procAttribs, // pointer to SECURITY_ATTRIBUTES struct here (defines descriptor).
		// we haven't done any modificatons for the other arguments up to this point.
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&sInfo,
		&pInfo
	);

	std::cout << GetLastError();
}


/*
		to-do

		fix error code 1337 regarding mainProc.
	

*/
