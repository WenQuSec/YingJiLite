using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace YingJiImage {
 public class Check {public bool Complete,Suspicious;public int Error,Compared,Changed,Masked;public long Address;public string Section="",Reason="",DiskSample="",MemorySample="";}
 public class Peek {public long Address,Base,Size;public uint Type,Protect,State;public int Error;public string MappedFile="",Sample="",ASCII="",UTF16="";}
 public static class Reader {
  [StructLayout(LayoutKind.Sequential)] struct MBI {public IntPtr BaseAddress,AllocationBase;public uint AllocationProtect;public UIntPtr RegionSize;public uint State,Protect,Type;}
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr a,byte[] b,UIntPtr n,out UIntPtr read);
  [DllImport("kernel32.dll",SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr a,out MBI b,UIntPtr size);
  [DllImport("psapi.dll",CharSet=CharSet.Unicode)] static extern uint GetMappedFileName(IntPtr h,IntPtr a,StringBuilder output,int count);
  static bool Read(IntPtr h,long at,byte[] b) {UIntPtr n;return ReadProcessMemory(h,new IntPtr(at),b,new UIntPtr((uint)b.Length),out n)&&n.ToUInt64()==(ulong)b.Length;}
  public static Peek InspectAddress(int pid,long address) {
   Peek p=new Peek{Address=address};IntPtr h=OpenProcess(0x410,false,pid);if(h==IntPtr.Zero){p.Error=Marshal.GetLastWin32Error();return p;}
   try {MBI m;if(VirtualQueryEx(h,new IntPtr(address),out m,new UIntPtr((uint)Marshal.SizeOf(typeof(MBI)))).ToUInt64()==0){p.Error=Marshal.GetLastWin32Error();return p;}
    p.Base=m.AllocationBase.ToInt64();p.Size=(long)m.RegionSize.ToUInt64();p.Type=m.Type;p.Protect=m.Protect;p.State=m.State;
    StringBuilder mapped=new StringBuilder(32768);if(GetMappedFileName(h,new IntPtr(address),mapped,mapped.Capacity)>0)p.MappedFile=mapped.ToString();
    long available=m.BaseAddress.ToInt64()+p.Size-address;int length=(int)Math.Min(512,Math.Max(0,available));byte[] b=new byte[length];
    if(length>0&&Read(h,address,b)){p.Sample=BitConverter.ToString(b,0,Math.Min(32,b.Length));p.ASCII=Encoding.ASCII.GetString(b);p.UTF16=Encoding.Unicode.GetString(b,0,b.Length-b.Length%2);}else p.Error=Marshal.GetLastWin32Error();
   }finally{CloseHandle(h);}return p;
  }
  static long Offset(long rva,List<long[]> sections) {foreach(long[] s in sections)if(rva>=s[0]&&rva<s[0]+s[1])return s[2]+rva-s[0];return -1;}
  public static Check InspectCode(int pid,string path,long address) {
   Check result=new Check{Address=address};IntPtr h=IntPtr.Zero;
   try {using(FileStream f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))using(BinaryReader r=new BinaryReader(f)) {
    if(f.Length<256||r.ReadUInt16()!=0x5a4d)return result;f.Position=60;uint pe=r.ReadUInt32();if(pe>f.Length-256)return result;
    f.Position=pe;if(r.ReadUInt32()!=17744)return result;f.Position=pe+6;int count=r.ReadUInt16();if(count<1||count>96)return result;
    f.Position=pe+20;int optional=r.ReadUInt16();f.Position=pe+24;int magic=r.ReadUInt16(),dd=magic==523?112:magic==267?96:0;if(dd==0||optional<dd+104)return result;
    f.Position=pe+24+dd+40;uint reloc=r.ReadUInt32(),relocSize=r.ReadUInt32();f.Position=pe+24+dd+96;uint iat=r.ReadUInt32(),iatSize=r.ReadUInt32();
    List<long[]> sections=new List<long[]>();long codeRva=0,codeRaw=0;int codeLength=0;
    for(int i=0;i<count;i++){f.Position=pe+24+optional+i*40;string name=Encoding.ASCII.GetString(r.ReadBytes(8)).TrimEnd('\0');uint virtualSize=r.ReadUInt32(),rva=r.ReadUInt32(),rawSize=r.ReadUInt32(),raw=r.ReadUInt32();f.Position=pe+24+optional+i*40+36;uint flags=r.ReadUInt32();sections.Add(new long[]{rva,rawSize,raw});
     if(codeLength==0&&(flags&0x20000000)!=0&&rawSize>0){codeRva=rva;codeRaw=raw;codeLength=(int)Math.Min(65536,Math.Min(rawSize,virtualSize));result.Section=name;}}
    if(codeLength<128||codeRaw+codeLength>f.Length)return result;bool[] mask=new bool[codeLength];long relocAt=Offset(reloc,sections);
    if(relocAt>=0&&relocSize<=1048576&&relocAt+relocSize<=f.Length){long end=relocAt+relocSize;f.Position=relocAt;while(f.Position+8<=end){uint page=r.ReadUInt32(),size=r.ReadUInt32();if(size<8||f.Position+size-8>end)break;int n=(int)(size-8)/2;for(int j=0;j<n;j++){ushort entry=r.ReadUInt16();int type=entry>>12,width=type==10?8:type==3?4:0;long pos=page+(entry&4095)-codeRva;for(int k=0;k<width;k++)if(pos+k>=0&&pos+k<codeLength)mask[pos+k]=true;}}}
    for(int i=0;i<codeLength;i++)if(codeRva+i>=iat&&codeRva+i<iat+iatSize)mask[i]=true;
    f.Position=codeRaw;byte[] disk=r.ReadBytes(codeLength),memory=new byte[codeLength];h=OpenProcess(0x410,false,pid);if(h==IntPtr.Zero){result.Error=Marshal.GetLastWin32Error();return result;}
    if(!Read(h,address+codeRva,memory)){result.Error=Marshal.GetLastWin32Error();return result;}int first=-1;
    for(int i=0;i<codeLength;i++){if(mask[i]){result.Masked++;continue;}result.Compared++;if(disk[i]!=memory[i]){result.Changed++;if(first<0)first=i;}}
    result.Complete=true;result.Suspicious=result.Changed>=64&&result.Changed*100L>=result.Compared*5L;
    if(first>=0){int n=Math.Min(16,codeLength-first);result.DiskSample=BitConverter.ToString(disk,first,n);result.MemorySample=BitConverter.ToString(memory,first,n);}
    result.Reason="Main image executable section differs from disk after masking base relocations and IAT; hotpatching, packing or security software can also cause differences; no injection verdict from this check alone";
   }}catch(Exception e){result.Reason=e.Message;}finally{if(h!=IntPtr.Zero)CloseHandle(h);}return result;
  }
 }
}