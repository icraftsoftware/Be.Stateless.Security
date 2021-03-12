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
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace Be.Stateless.Runtime
{
	[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
	internal sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
	{
		#region Nested Type: NativeMethods

		private static class NativeMethods
		{
			[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			[SuppressUnmanagedCodeSecurity]
			[return: MarshalAs(UnmanagedType.Bool)]
			internal static extern bool CloseHandle(IntPtr handle);
		}

		#endregion

		private SafeTokenHandle() : base(true) { }

		#region Base Class Member Overrides

		protected override bool ReleaseHandle()
		{
			return NativeMethods.CloseHandle(handle);
		}

		#endregion
	}
}
