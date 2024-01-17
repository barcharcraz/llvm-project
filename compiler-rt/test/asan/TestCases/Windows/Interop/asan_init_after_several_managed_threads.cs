using System;
using System.Threading;
using System.Reflection;
using System.Runtime.InteropServices;

public class ThreadExample
{
    internal class ThreadTask { }
    static int threadNum = 0;
    static int threadPool = 1000;
    static Random rnd = new Random();
    private static async Task<ThreadTask> StartAThread(int num)
    {
        var myCount = threadNum;
        threadNum++;
        await Task.Delay(rnd.Next(1,100));

        if (num == threadPool / 2)
        {
            Console.WriteLine($"Loading ASAN.");
            NativeLibrary.Load("memory_with_asan_dll.dll");
        }

        Marshal.AllocHGlobal(16);
        return new ThreadTask();
    }


    // This would not fail every run prior to the ASAN initialization changes.
    // It would fail every ~5-10 runs.
    static async Task Main(string[] args)
    {
        Console.WriteLine("Starting main");

        var threads = new List<Task> { };
        for (int i = 0; i < threadPool; ++i)
        {
            threads.Add(StartAThread(i));
        }

        Console.WriteLine("Threads are made!");

        while (threads.Count > 0)
        {
            Task finishedTask = await Task.WhenAny(threads);
            await finishedTask;
            threads.Remove(finishedTask);
        }

        Console.WriteLine("All done!");
    }
}