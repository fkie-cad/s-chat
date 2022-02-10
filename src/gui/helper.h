#ifndef HELPER_H
#define HELPER_H

#include <windows.h>

PCHAR*
CommandLineToArgvA(
	PCHAR CmdLine,
	int* _argc
)
{
	PCHAR* argv;
	PCHAR _argv;
	ULONG len;
	ULONG argc;
	CHAR a;
	ULONG i, j;

	BOOLEAN in_QM;
	BOOLEAN in_TEXT;
	BOOLEAN in_SPACE;

	len = (ULONG)strlen(CmdLine);
	if ( len == 0 )
	{
		*_argc = 0;
		return NULL;
	}
	i = ((len + 2) / 2) * (ULONG)sizeof(PVOID) + (ULONG)sizeof(PVOID);

	ULONG argvSize = i + (len + 2) * (ULONG)sizeof(CHAR);
	if ( argvSize == 0 )
	{
		*_argc = 0;
		return NULL;
	}

	argv = (PCHAR*)HeapAlloc(GetProcessHeap(), 0, argvSize);
	if ( !argv )
	{
		*_argc = 0;
		return NULL;
	}

	_argv = (PCHAR)(((PUCHAR)argv) + i);

	argc = 0;
	argv[argc] = _argv;
	in_QM = FALSE;
	in_TEXT = FALSE;
	in_SPACE = TRUE;
	i = 0;
	j = 0;
	
	a = CmdLine[i];
	while ( a )
	{
		if ( in_QM )
		{
			if ( a == '\"' )
			{
				in_QM = FALSE;
			}
			else
			{
				_argv[j] = a;
				j++;
			}
		}
		else
		{
			switch ( a )
			{
			case '\"':
				in_QM = TRUE;
				in_TEXT = TRUE;
				if ( in_SPACE )
				{
					argv[argc] = _argv + j;
					argc++;
				}
				in_SPACE = FALSE;
				break;
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				if ( in_TEXT )
				{
					_argv[j] = '\0';
					j++;
				}
				in_TEXT = FALSE;
				in_SPACE = TRUE;
				break;
			default:
				in_TEXT = TRUE;
				if ( in_SPACE )
				{
					argv[argc] = _argv + j;
					argc++;
				}
				_argv[j] = a;
				j++;
				in_SPACE = FALSE;
				break;
			}
		}
		i++;
		a = CmdLine[i];
	}
	_argv[j] = '\0';
	argv[argc] = NULL;

	(*_argc) = argc;
	return argv;
}

#endif
