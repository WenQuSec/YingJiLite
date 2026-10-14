using System;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace YingJiJournal {
 public class Change { public string Path,Name,FileId,ParentId,TimeUtc; public uint Reason; public bool PathResolved; }
 public class Result { public string Volume; public int Error,Records,Unsupported; public bool Complete; public List<Change> Changes=new List<Change>(); }
 public static class Reader {
  [StructLayout(LayoutKind.Sequential)] struct ReadData { public long Start; public uint Mask,CloseOnly; public ulong Timeout,Wait,Id; }
  [StructLayout(LayoutKind.Sequential)] struct FileId { public uint Size,Type; public ulong Id,Extra; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(IntPtr h,uint ctl,IntPtr input,int inSize,byte[] output,int outSize,out int returned,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenFileById(IntPtr h,ref FileId id,uint access,uint share,IntPtr sa,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr h,StringBuilder name,uint len,uint flags);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  static string Resolve(IntPtr volume,ulong number,Dictionary<ulong,string> cache){
   string value;if(cache.TryGetValue(number,out value))return value;
   FileId id=new FileId{Size=24,Type=0,Id=number};IntPtr h=OpenFileById(volume,ref id,0x80,7,IntPtr.Zero,0x02000000);
   value="";if(h!=new IntPtr(-1)){try{StringBuilder b=new StringBuilder(32768);uint n=GetFinalPathNameByHandle(h,b,(uint)b.Capacity,0);if(n>0&&n<b.Capacity){value=b.ToString();if(value.StartsWith("\\\\?\\"))value=value.Substring(4);}}finally{CloseHandle(h);}}
   cache[number]=value;return value;
  }
  public static Result Read(string drive,long[] centers,int milliseconds){
   Result result=new Result();result.Volume=drive;Stopwatch timer=Stopwatch.StartNew();
   IntPtr h=CreateFile("\\\\.\\"+drive,0x80000000,7,IntPtr.Zero,3,0,IntPtr.Zero);
   if(h==new IntPtr(-1)){result.Error=Marshal.GetLastWin32Error();return result;}
   IntPtr request=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ReadData)));
   try {
    byte[] query=new byte[80];int got;if(!DeviceIoControl(h,0x900f4,IntPtr.Zero,0,query,query.Length,out got,IntPtr.Zero)||got<56){result.Error=Marshal.GetLastWin32Error();return result;}
    ReadData rd=new ReadData{Start=BitConverter.ToInt64(query,8),Mask=0xffffffff,Id=BitConverter.ToUInt64(query,0)};long end=BitConverter.ToInt64(query,16);
    byte[] buffer=new byte[1024*1024];Dictionary<ulong,string> cache=new Dictionary<ulong,string>();
    while(rd.Start<end&&timer.ElapsedMilliseconds<milliseconds){
     Marshal.StructureToPtr(rd,request,false);
     if(!DeviceIoControl(h,0x900bb,request,Marshal.SizeOf(typeof(ReadData)),buffer,buffer.Length,out got,IntPtr.Zero)||got<8){result.Error=Marshal.GetLastWin32Error();break;}
     long next=BitConverter.ToInt64(buffer,0);if(next<=rd.Start)break;
     for(int off=8;off+60<=got;){
      int len=BitConverter.ToInt32(buffer,off);if(len<60||len>got-off)break;int version=BitConverter.ToUInt16(buffer,off+4);result.Records++;
      if(version!=2){result.Unsupported++;off+=len;continue;}
      long stamp=BitConverter.ToInt64(buffer,off+32);bool near=false;foreach(long c in centers){if(stamp>=c-TimeSpan.TicksPerMinute*2&&stamp<=c+TimeSpan.TicksPerMinute*2){near=true;break;}}
      uint reason=BitConverter.ToUInt32(buffer,off+40),attributes=BitConverter.ToUInt32(buffer,off+52);
      int chars=BitConverter.ToUInt16(buffer,off+56),start=BitConverter.ToUInt16(buffer,off+58);
      if(near&&(reason&0x00003303)!=0&&(attributes&0x10)==0&&start>=60&&start+chars<=len){
       ulong id=BitConverter.ToUInt64(buffer,off+8),parent=BitConverter.ToUInt64(buffer,off+16);string name=Encoding.Unicode.GetString(buffer,off+start,chars);
       string path=Resolve(h,id,cache);if(path.Length==0){string folder=Resolve(h,parent,cache);if(folder.Length>0)path=folder.TrimEnd('\\')+"\\"+name;}
       result.Changes.Add(new Change{Path=path,Name=name,FileId=id.ToString(),ParentId=parent.ToString(),TimeUtc=DateTime.FromFileTimeUtc(stamp).ToString("o"),Reason=reason,PathResolved=path.Length>0});
       if(result.Changes.Count>=4000)return result;
      }
      off+=len;
     }
     rd.Start=next;
    }
    result.Complete=rd.Start>=end;
   }finally{Marshal.FreeHGlobal(request);CloseHandle(h);}return result;
  }
 }
}