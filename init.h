#pragma once

class init
{
private:
public:
	SECURITY_DESCRIPTOR security_descriptor_init() 
	{
		SECURITY_DESCRIPTOR secObjInfo{}; // contains info such as, owner, group, Sacl, Dacl, control. (Important)

		// SID structure stuff
		SID_IDENTIFIER_AUTHORITY sia
		{
			5
		};
		PSID si{}; // this security identification object determines what level of authority we have. 

		BOOL sid = AllocateAndInitializeSid( // function to initialize our 
			&sia,
			1,
			0x000001F4,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			&si
		);
		//std::cout << sid;
		// END OF

		// set revision level and give default initialization to mostly everything else in the struct (SECURITY_DESCRIPTOR). 

		BOOL setRevision = InitializeSecurityDescriptor(
			&secObjInfo,
			SECURITY_DESCRIPTOR_REVISION
		);

		// end 

		// set owner of SECURITY_DESCRIPTOR

		BOOL secDesOwner = SetSecurityDescriptorOwner(
			&secObjInfo,
			&si,
			0
		);

		// end 

		// set group for SECURITY_DESCRIPTOR
		BOOL secDesGroup = SetSecurityDescriptorGroup(
			&secObjInfo,
			&si,
			0
		);

		return secObjInfo;
	}
};
