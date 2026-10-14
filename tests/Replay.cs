using System;
using System.IO;
using System.Reflection;

class Replay {
    [STAThread]
    static int Main(string[] args) {
        try {
            var assembly = Assembly.LoadFile(Path.GetFullPath(args[0]));
            var run = assembly.GetType("YingJiRuntime.Collector").GetMethod("Run");
            return (int)run.Invoke(null, new object[] {
                Path.GetFullPath(args[1]), 72, Path.GetFullPath(args[2]),
                (Action<string>)(message => Console.WriteLine(message))
            });
        } catch (Exception e) {
            Console.Error.WriteLine(e);
            return 1;
        }
    }
}
