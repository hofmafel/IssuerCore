using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;

namespace IssuerCore
{
    internal class Program
    {
        private static Mutex mutex = new Mutex();
        static List<String> domains;
        static SortedDictionary<string, int> count;       
              
        /**
         * load domains from file (comma seperated list)
         * format: n,<domain>
         * return true if successful. Otherwise, return false.
         */
        static bool loadDomains()
        {
            try
            {
                using (StreamReader reader = new StreamReader("top-1m.csv"))
                {
                    string line;
                    int index;
                    
                    //while not EOF
                    while ((line = reader.ReadLine()) != null)
                    {
                        index = line.IndexOf(',') + 1;
                        domains.Add(line.Substring(index, line.Length - index));
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error reading file:");
                Console.WriteLine(e.Message);
                return false;
            }

            return true;
        }

        /** Main
         * First initializes containers, load domains,
         * then, loaded domains are checked concurrently for
         * which CA issued the X.509 certificate.
         * 
         * threadThreshold: how many concurrent tasks to run
         * ideal for 5Gbit+/s 32+ core AWS EC2: 25000
         * for desktop-pc: 50-5000
         */
        static async Task Main()
        {
            domains = new List<string>();
            count = new SortedDictionary<string, int>();
            var connectionTasks = new List<Task>();
     
            if(!loadDomains())
                return;

            //imrove speed by avoiding exceptions
            count.Add("Domains Tested", 0);
            count.Add("HTTP-Exceptions", 0);
            count.Add("Certificate invalid", 0);

            //How many Tasks to run simultaneously
            int threadThreshold = 1000;
            
            //keep track of domains checked
            int cycles = 1;
            int domainsChecked = 0;

            foreach (String domain in domains)
            {
                    connectionTasks.Add(checkDomain(domain));

                //Task pool is exceeded, wait until some Tasks finish   
                    while (connectionTasks.Count > threadThreshold)
                    {
                        //wait for any task to finish
                        Task finishedTask = await Task.WhenAny(connectionTasks);
                        connectionTasks.Remove(finishedTask);
                        domainsChecked++;

                        if (domainsChecked > 99)
                        {
                            Console.WriteLine("{0} Domains Checked", domainsChecked * cycles);
                            cycles++;
                            domainsChecked = 0;

                        }

                    }
            }
            
            //Wait for any remaining Tasks to finish
            while (connectionTasks.Count > 0)
            {
                Task finishedTask = await Task.WhenAny(connectionTasks);
                connectionTasks.Remove(finishedTask);
                domainsChecked++;

                if (domainsChecked > 99)
                {
                    Console.WriteLine("{0} Domains Checked", domainsChecked * cycles);
                    cycles++;
                    domainsChecked = 0;

                }

            }

            //save results
            using (StreamWriter writer = new StreamWriter("statistics.txt"))
            {
                foreach (KeyValuePair<string, int> keyValue in count)
                {
                    writer.WriteLine("{0},{1}", keyValue.Key, keyValue.Value);
                }

            }

            //sanity check: domains loaded == domains tested
            Trace.Assert(count["Domains Tested"] == domains.Count, "Domains Tested unequal domains loaded!");


        }
        static void addToEntry(String name)
        {
            mutex.WaitOne();
            try
            {
                count.Add(name, 1);
            }
            catch (ArgumentException)
            {
                //Entry exists already
                count[name] = count[name] + 1;
            }
            mutex.ReleaseMutex();
        }

        /**
         * Check which CA issued certificate by connecting. 
         *
         */
        static async Task checkDomain(String domain)
        {
            HttpClientHandler handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = validateCertificate;
            HttpClient client = new HttpClient(handler);

            
            addToEntry("Domains Tested");
            try
            {
                HttpResponseMessage response0 = await client.GetAsync("https://" + domain);

                response0.EnsureSuccessStatusCode();

            }
            catch (HttpRequestException exception0)
            {
                
                addToEntry("HTTP-Exceptions");

            }

            handler.Dispose();
            client.Dispose();

        }
        /**
         * custom validation function, keeps track of which CA issued certificate.
         * If certificate is invalid or other SslPolicyErrors are encountered, dont count the certificate and return false
         */
        private static bool validateCertificate(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            /*
                additional properties:
                requestMessage.RequestUri
                certificate.GetEffectiveDateString()
                certificate.GetExpirationDateString()
                certificate.Issuer
                certificate.Subject
             */

            //Certificate could not be verified or is invalid
            if(sslErrors != SslPolicyErrors.None)
            {
                
                addToEntry("Certificate invalid");
                return false;
            }
            
            String issuer = $"{certificate.Issuer}";
            
            //extract issuer organisation name
            int start = issuer.IndexOf("O=") + 2;
            int end = start;
            while (issuer[end] != ',')
                end++;
            if (issuer[start] == '"')
                start++;
            try
            {
                issuer = issuer.Substring(start, end - start);
            }
            catch (ArgumentOutOfRangeException e)
            {
                Console.WriteLine("issuer = issuer.Substring(start, end - start);: Out of range.");
            }

            addToEntry(issuer);
            return true;
        }
    }
}
