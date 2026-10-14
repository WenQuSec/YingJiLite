using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace YingJiMemory {
 public class Hit { public long Address,Allocation,Size; public string Kind,Reason; public uint Protection,MemoryType; public int ThreadId; }
 public class Scan { public int Pid,Regions,ReadFailures,ThreadFailures; public long BytesRead; public bool Opened,Complete; public int Error; public List<Hit> Hits=new List<Hit>(); }
 public class Region { public long Address,Allocation,Size; public uint Protect,Type; public bool Executable; }
 public class LoadedModule { public string Path,Name; public long Address; public uint Size; }
 public class ModuleScan { public int Pid,Error; public bool Complete; public List<LoadedModule> Modules=new List<LoadedModule>(); }
 public static class Reader {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct MODULEENTRY32 {
   public uint dwSize,th32ModuleID,th32ProcessID,GlblcntUsage,ProccntUsage;
   public IntPtr modBaseAddr;public uint modBaseSize;public IntPtr hModule;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string szModule;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string szExePath;
  }
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Module32First(IntPtr snapshot,ref MODULEENTRY32 entry);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Module32Next(IntPtr snapshot,ref MODULEENTRY32 entry);
  public static ModuleScan Modules(int pid) {
   ModuleScan result=new ModuleScan{Pid=pid};IntPtr snapshot=new IntPtr(-1);
   for(int i=0;i<3;i++){snapshot=CreateToolhelp32Snapshot(0x18,(uint)pid);if(snapshot!=new IntPtr(-1))break;result.Error=Marshal.GetLastWin32Error();if(result.Error!=24)return result;}
   if(snapshot==new IntPtr(-1))return result;
   try { MODULEENTRY32 entry=new MODULEENTRY32();entry.dwSize=(uint)Marshal.SizeOf(typeof(MODULEENTRY32));
    if(!Module32First(snapshot,ref entry)){result.Error=Marshal.GetLastWin32Error();return result;}
    do { result.Modules.Add(new LoadedModule{Path=entry.szExePath,Name=entry.szModule,Address=entry.modBaseAddr.ToInt64(),Size=entry.modBaseSize});entry.dwSize=(uint)Marshal.SizeOf(typeof(MODULEENTRY32)); }while(result.Modules.Count<4096&&Module32Next(snapshot,ref entry));
    result.Error=Marshal.GetLastWin32Error();result.Complete=result.Error==18;if(result.Complete)result.Error=0;
   }finally{CloseHandle(snapshot);}return result;
  }
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TOKEN_PRIVILEGES privileges,int size,IntPtr previous,IntPtr returned);
  public static bool EnableDebugPrivilege() {
   IntPtr t;if(!OpenProcessToken(Process.GetCurrentProcess().Handle,0x28,out t))return false;
   try { LUID l;if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out l))return false;
    TOKEN_PRIVILEGES p=new TOKEN_PRIVILEGES{Count=1,Luid=l,Attributes=2};return AdjustTokenPrivileges(t,false,ref p,0,IntPtr.Zero,IntPtr.Zero)&&Marshal.GetLastWin32Error()==0;
   }finally{CloseHandle(t);}
  }
  [StructLayout(LayoutKind.Sequential)] struct MBI { public IntPtr BaseAddress,AllocationBase; public uint AllocationProtect; public UIntPtr RegionSize; public uint State,Protect,Type; }
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr a,out MBI b,UIntPtr size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,UIntPtr n,out UIntPtr read);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,int id);
  [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h,int cls,out IntPtr address,int size,IntPtr returned);
  static bool Exec(uint p) { return (p & 0xF0)!=0 && (p & 0x100)==0; }
  public static bool PE(byte[] b,long allocationSize) {
   if(b.Length<96||b[0]!=77||b[1]!=90)return false;
   int p=BitConverter.ToInt32(b,60);if(p<64||p>b.Length-26||BitConverter.ToUInt32(b,p)!=17744)return false;
   int machine=BitConverter.ToUInt16(b,p+4),sections=BitConverter.ToUInt16(b,p+6),opt=BitConverter.ToUInt16(b,p+20),magic=BitConverter.ToUInt16(b,p+24);
   return (machine==332||machine==34404||machine==43620)&&sections>0&&sections<=96&&opt>=96&&opt<=512&&(magic==267||magic==523)&&p+24+opt+sections*40<=allocationSize;
  }
  public static Scan Inspect(int pid,int milliseconds) {
   Scan result=new Scan();result.Pid=pid;Stopwatch timer=Stopwatch.StartNew();
   IntPtr h=OpenProcess(0x410,false,pid);if(h==IntPtr.Zero){result.Error=Marshal.GetLastWin32Error();return result;}result.Opened=true;
   try {
    List<Region> regions=new List<Region>();HashSet<long> executable=new HashSet<long>();Dictionary<long,long> extent=new Dictionary<long,long>();
    long cursor=0;bool enumerated=false;int mbiSize=Marshal.SizeOf(typeof(MBI));
    while(timer.ElapsedMilliseconds<milliseconds&&result.Regions<200000) {
     MBI m;if(VirtualQueryEx(h,new IntPtr(cursor),out m,new UIntPtr((uint)mbiSize)).ToUInt64()==0){enumerated=true;break;}
     long address=m.BaseAddress.ToInt64(),size=(long)m.RegionSize.ToUInt64(),allocation=m.AllocationBase.ToInt64();
     if(size<=0||address>long.MaxValue-size||address+size<=cursor)break;cursor=address+size;result.Regions++;
     if(m.State!=0x1000||(m.Protect&0x101)!=0)continue;
     Region r=new Region{Address=address,Allocation=allocation,Size=size,Protect=m.Protect,Type=m.Type,Executable=Exec(m.Protect)};
     if(m.Type!=0x20000&&m.Type!=0x40000)continue;regions.Add(r);
     long end=address+size-allocation;if(!extent.ContainsKey(allocation)||extent[allocation]<end)extent[allocation]=end;
     if(r.Executable)executable.Add(allocation);
    }
    HashSet<long> inspected=new HashSet<long>();HashSet<long> peAllocations=new HashSet<long>();
    foreach(Region r in regions) {
     if(timer.ElapsedMilliseconds>=milliseconds)break;
     if(!executable.Contains(r.Allocation)||!inspected.Add(r.Allocation))continue;
     byte[] b=new byte[4096];UIntPtr read;
     if(!ReadProcessMemory(h,new IntPtr(r.Allocation),b,new UIntPtr((uint)b.Length),out read)||read.ToUInt64()<96){result.ReadFailures++;continue;}
     result.BytesRead+=(long)read.ToUInt64();
     if(PE(b,extent[r.Allocation])) { peAllocations.Add(r.Allocation); result.Hits.Add(new Hit{Address=r.Allocation,Allocation=r.Allocation,Size=extent[r.Allocation],Protection=r.Protect,MemoryType=r.Type,Kind="NonImageExecutablePE",Reason="Valid PE header in a private/mapped allocation with executable pages; not a normal MEM_IMAGE mapping"}); }
    }
    if(timer.ElapsedMilliseconds<milliseconds) {
     try { using(Process process=Process.GetProcessById(pid)) { foreach(ProcessThread thread in process.Threads) {
      if(timer.ElapsedMilliseconds>=milliseconds)break;IntPtr th=OpenThread(0x40,false,thread.Id);if(th==IntPtr.Zero){result.ThreadFailures++;continue;}
      try {IntPtr start;if(NtQueryInformationThread(th,9,out start,IntPtr.Size,IntPtr.Zero)!=0){result.ThreadFailures++;continue;}
       long a=start.ToInt64();foreach(Region r in regions){if(r.Executable&&a>=r.Address&&a-r.Address<r.Size){result.Hits.Add(new Hit{Address=a,Allocation=r.Allocation,Size=r.Size,Protection=r.Protect,MemoryType=r.Type,ThreadId=thread.Id,Kind=peAllocations.Contains(r.Allocation)?"ThreadInNonImagePE":"ThreadInNonImageExecutable",Reason="Thread start address is in private/mapped executable memory; JIT and legitimate dynamic code may also match"});break;}}
      } finally {CloseHandle(th);}
     } } } catch {result.ThreadFailures++;}
    }
    result.Complete=enumerated&&timer.ElapsedMilliseconds<milliseconds;
   } finally {CloseHandle(h);}return result;
  }
 }
}