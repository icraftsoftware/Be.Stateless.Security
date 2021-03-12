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
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using Be.Stateless.Extensions;

namespace Be.Stateless.Security.Principal
{
	/// <summary>
	/// </summary>
	/// <seealso href="http://msdn.microsoft.com/en-us/library/system.security.principal.windowsimpersonationcontext.aspx"/>
	/// <seealso href="http://www.cstruter.com/blog/270"/>
	internal class WindowsIdentity
	{
		#region Nested Type: NativeMethods

		private static class NativeMethods
		{
			#region CredUIReturnCode Enum

			/// <summary>
			/// http://www.pinvoke.net/default.aspx/Enums.CredUIReturnCodes
			/// </summary>
			[SuppressMessage("ReSharper", "InconsistentNaming")]
			internal enum CredUIReturnCode
			{
				NO_ERROR = 0,
				ERROR_INVALID_PARAMETER = 87,
				ERROR_INSUFFICIENT_BUFFER = 122,
				ERROR_BAD_ARGUMENTS = 160,
				ERROR_INVALID_FLAGS = 1004,
				ERROR_NOT_FOUND = 1168,
				ERROR_CANCELLED = 1223,
				ERROR_NO_SUCH_LOGON_SESSION = 1312,
				ERROR_INVALID_ACCOUNT_NAME = 1315
			}

			#endregion

			/// <summary>
			/// http://www.pinvoke.net/default.aspx/credui/CredUIParseUserName.html
			/// </summary>
			[SuppressMessage("ReSharper", "StringLiteralTypo")]
			[DllImport("credui.dll", EntryPoint = "CredUIParseUserNameW", CharSet = CharSet.Unicode)]
			internal static extern CredUIReturnCode CredUIParseUserName(
				string userName,
				StringBuilder user,
				int userMaxChars,
				StringBuilder domain,
				int domainMaxChars);
		}

		#endregion

		/// <summary>
		/// Extracts the domain and user account name from a fully qualified user name.
		/// </summary>
		/// <param name="username">
		/// A <see cref="string"/> that contains the user name to be parsed. The name must be in UPN or down-level format, or a
		/// certificate.
		/// </param>
		/// <param name="user">
		/// A <see cref="string"/> that receives the user account name.
		/// </param>
		/// <param name="domain">
		/// A <see cref="string"/> that receives the domain name. If <paramref name="username"/> specifies a certificate,
		/// pszDomain will be <see langword="null"/>.
		/// </param>
		/// <returns>
		/// <see langword="true"/> if the <paramref name="username"/> contains a domain and a user-name; otherwise, <see
		/// langword="false"/>.
		/// </returns>
		/// <seealso href="http://www.pinvoke.net/default.aspx/credui.creduiparseusername"/>
		private static void ParseUserName(string username, out string user, out string domain)
		{
			if (username.IsNullOrEmpty()) throw new ArgumentNullException(nameof(username));

			var userBuilder = new StringBuilder();
			var domainBuilder = new StringBuilder();
			var code = NativeMethods.CredUIParseUserName(username, userBuilder, int.MaxValue, domainBuilder, int.MaxValue);
			switch (code)
			{
				case NativeMethods.CredUIReturnCode.NO_ERROR:
					user = userBuilder.ToString();
					domain = domainBuilder.ToString();
					break;

				case NativeMethods.CredUIReturnCode.ERROR_CANCELLED:
					throw new Exception("Canceled.");

				case NativeMethods.CredUIReturnCode.ERROR_NO_SUCH_LOGON_SESSION:
					throw new Exception("No such logon session.");

				case NativeMethods.CredUIReturnCode.ERROR_NOT_FOUND:
					throw new Exception("Not found.");

				case NativeMethods.CredUIReturnCode.ERROR_INVALID_ACCOUNT_NAME:
					throw new Exception($"Invalid account name ({username}).");

				case NativeMethods.CredUIReturnCode.ERROR_INSUFFICIENT_BUFFER:
					throw new Exception("Insufficient buffer.");

				case NativeMethods.CredUIReturnCode.ERROR_BAD_ARGUMENTS:
					throw new Exception("Bad arguments.");

				case NativeMethods.CredUIReturnCode.ERROR_INVALID_PARAMETER:
					throw new Exception("Invalid parameter.");

				case NativeMethods.CredUIReturnCode.ERROR_INVALID_FLAGS:
					throw new Exception("Invalid flags.");

				default:
					throw new Exception("Unknown credential result encountered.");
			}
		}

		public WindowsIdentity(string userName, string password)
		{
			UserName = userName;
			Password = password;
		}

		[SuppressMessage("ReSharper", "MemberCanBePrivate.Global", Justification = "Public API.")]
		public string Password { get; }

		[SuppressMessage("ReSharper", "MemberCanBePrivate.Global", Justification = "Public API.")]
		public string UserName { get; }

		public IDisposable Impersonate()
		{
			ParseUserName(UserName, out var username, out var domain);
			return new ImpersonationContext(username, domain, Password);
		}
	}
}
