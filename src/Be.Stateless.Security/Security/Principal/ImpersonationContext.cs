#region Copyright & License

// Copyright © 2012 - 2021 François Chabot
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#endregion

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Be.Stateless.Runtime;

namespace Be.Stateless.Security.Principal
{
	internal class ImpersonationContext : IDisposable
	{
		#region Nested Type: NativeMethods

		private static class NativeMethods
		{
			[SuppressMessage("ReSharper", "StringLiteralTypo")]
			[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			internal static extern bool LogonUser(
				string lpszUsername,
				string lpszDomain,
				string lpszPassword,
				int dwLogonType,
				int dwLogonProvider,
				out SafeTokenHandle phToken);
		}

		#endregion

		public ImpersonationContext(string username, string domain, string password)
		{
			var result = NativeMethods.LogonUser(username, domain, password, (int) LogonType.NewCredentials, (int) LogonProvider.WinNT50, out _safeTokenHandle);
			if (!result) throw new Win32Exception(Marshal.GetLastWin32Error());
			_windowsImpersonationContext = new System.Security.Principal.WindowsIdentity(_safeTokenHandle.DangerousGetHandle()).Impersonate();
		}

		~ImpersonationContext()
		{
			Dispose();
		}

		#region IDisposable Members

		public void Dispose()
		{
			_windowsImpersonationContext?.Dispose();
			_safeTokenHandle?.Dispose();
			GC.SuppressFinalize(this);
		}

		#endregion

		private readonly SafeTokenHandle _safeTokenHandle;
		private readonly WindowsImpersonationContext _windowsImpersonationContext;
	}
}
