using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SureCred
{
    class Program
    {
        static List<Credentials> ActiveCreds = new List<Credentials>();
        static List<Credentials> CurrentCreds = new List<Credentials>();
        static List<Credentials> UpdatedCreds = new List<Credentials>();
        static string EncryptionKey { get; set; }
        static string InitVector { get; set; }

        static Aes256 security;

        static void Main(string[] args)
        {
            EncryptionKey = ConfigurationManager.AppSettings["ecrKey"].ToString();
            InitVector = ConfigurationManager.AppSettings["ecrIv"].ToString();
            LoadActive();
            LoadCurrent();
            CompareCreds();
            if (UpdatedCreds.Count > 0)
            {
                UploadCreds();
            }
        }

        private static void UploadCreds()
        {
            foreach (Credentials cred in UpdatedCreds)
            {
                if (cred.IsHD)
                {
                    using (SqlConnection app = new SqlConnection(ConfigurationManager.ConnectionStrings["USAT"].ToString()))
                    {
                        string sql = @"if not exists (select 1 from parameters where serialnumber = @sn) 
                                    begin
	                                    insert into parameters (serialnumber, mid, tid, siteid, licenseid, datelastupdated)
	                                    values
	                                    (@sn, @mid, @tid, @siteid, @licenseid, getdate())
                                    end
                                    else
                                    begin
	                                    update parameters
		                                    set mid = @mid,
		                                    tid = @tid,
                                            datelastupdated = getdate()
	                                    where serialnumber = @sn
                                    end";
                        SqlCommand cmd = new SqlCommand(sql, app);
                        cmd.Parameters.Add("@sn", SqlDbType.VarChar).Value = cred.SerialNumber;
                        cmd.Parameters.Add("@mid", SqlDbType.VarChar).Value = cred.MID;
                        cmd.Parameters.Add("@tid", SqlDbType.VarChar).Value = cred.TID;
                        cmd.Parameters.Add("@siteid", SqlDbType.VarChar).Value = cred.SiteId;
                        cmd.Parameters.Add("@licenseid", SqlDbType.VarChar).Value = cred.LicenseId;
                        app.Open();
                        cmd.ExecuteNonQuery();
                        app.Close();
                    }
                    using (SqlConnection app = new SqlConnection(ConfigurationManager.ConnectionStrings["Payments"].ToString()))
                    {
                        string sql = @"if not exists (select 1 from parameters where serialnumber = @sn) 
                                    begin
	                                    insert into parameters (serialnumber, mid, tid, siteid, licenseid, datelastupdated)
	                                    values
	                                    (@sn, @mid, @tid, @siteid, @licenseid, getdate())
                                    end
                                    else
                                    begin
	                                    update parameters
		                                    set mid = @mid,
		                                    tid = @tid,
                                            datelastupdated = getdate()
	                                    where serialnumber = @sn
                                    end";
                        SqlCommand cmd = new SqlCommand(sql, app);
                        cmd.Parameters.Add("@sn", SqlDbType.VarChar).Value = cred.SerialNumber;
                        cmd.Parameters.Add("@mid", SqlDbType.VarChar).Value = cred.MID;
                        cmd.Parameters.Add("@tid", SqlDbType.VarChar).Value = cred.TID;
                        cmd.Parameters.Add("@siteid", SqlDbType.VarChar).Value = cred.SiteId;
                        cmd.Parameters.Add("@licenseid", SqlDbType.VarChar).Value = cred.LicenseId;
                        app.Open();
                        cmd.ExecuteNonQuery();
                        app.Close();
                    }
                }
                else
                {
                    using (SqlConnection app = new SqlConnection(ConfigurationManager.ConnectionStrings["USAT"].ToString()))
                    {
                        string sql = @"if not exists (select 1 from parameters where serialnumber = @sn) 
                                    begin
	                                    insert into parameters (serialnumber, mid, tid, siteid, licenseid, datelastupdated)
	                                    values
	                                    (@sn, @mid, @tid, @siteid, @licenseid, getdate())
                                    end
                                    else
                                    begin
	                                    update parameters
		                                    set mid = @mid,
		                                    tid = @tid,
                                            datelastupdated = getdate()
	                                    where serialnumber = @sn
                                    end";
                        SqlCommand cmd = new SqlCommand(sql, app);
                        cmd.Parameters.Add("@sn", SqlDbType.VarChar).Value = cred.SerialNumber;
                        cmd.Parameters.Add("@mid", SqlDbType.VarChar).Value = cred.MID;
                        cmd.Parameters.Add("@tid", SqlDbType.VarChar).Value = cred.TID;
                        cmd.Parameters.Add("@siteid", SqlDbType.VarChar).Value = cred.SiteId;
                        cmd.Parameters.Add("@licenseid", SqlDbType.VarChar).Value = cred.LicenseId;
                        app.Open();
                        cmd.ExecuteNonQuery();
                        app.Close();
                    }
                }
            }
        }

        private static void CompareCreds()
        {
            foreach (Credentials cred in CurrentCreds)
            {
                var Update = ActiveCreds.Where(o => o.SerialNumber == cred.SerialNumber && (o.MID != cred.MID || o.TID != cred.TID)).FirstOrDefault();
                if (Update != null)
                {
                    UpdatedCreds.Add(Update);
                }
            }
            HashSet<string> SNs = new HashSet<string>(CurrentCreds.Select(s => s.SerialNumber));
            var Updates = ActiveCreds.Where(m => !SNs.Contains(m.SerialNumber));
            foreach(Credentials cred in Updates)
            {
                UpdatedCreds.Add(cred);
            }
        }

        private static void LoadCurrent()
        {
            using (SqlConnection apps = new SqlConnection(ConfigurationManager.ConnectionStrings["USAT"].ToString()))
            {
                string sql = @"select 
	                            serialnumber,
	                            mid,
	                            tid
                            from usat.dbo.parameters";
                SqlCommand cmd = new SqlCommand(sql, apps);
                apps.Open();
                SqlDataReader sdr = cmd.ExecuteReader();
                while (sdr.Read())
                {
                    Credentials NewCred = new Credentials();
                    NewCred.SerialNumber = sdr[0].ToString();
                    NewCred.MID = EncryptData(sdr[1].ToString());
                    NewCred.TID = EncryptData(sdr[2].ToString());
                    CurrentCreds.Add(NewCred);
                }
            }
        }

        private static void LoadActive()
        {
            using (SqlConnection apps = new SqlConnection(ConfigurationManager.ConnectionStrings["Apps"].ToString()))
            {
                string sql = string.Empty;
                if (apps.ConnectionString.Contains("74.112.192."))
                {
                    sql = @"declare @tbl table (SerialNumber varchar(20), mid varchar(100), tid varchar(100), gmid varchar(100), gtid varchar (100), siteid varchar(100), licenseid varchar(100), isoti bit, ishd bit)
                                insert into @tbl(SerialNumber, mid, tid, gmid, gtid, siteid, licenseid)
                                select
                                    k.SerialNumber,
	                                m.mid,
	                                t.tid,
	                                isnull(kcsm.FieldValue, '') 'gmid',
	                                isnull(kcst.FieldValue, '') 'gtid',
	                                isnull(kcss.FieldValue, '') 'siteid',
	                                isnull(kcsl.FieldValue, '') 'licenseid'
                                from KioskConfiguration kc
                                    join kiosk k on k.KioskId = kc.KioskId
                                    join mid m on m.midid = kc.MidId
                                    join tid t on t.tidid = kc.TidId
                                    left join KioskConfigurationSetting kcsm on kcsm.KioskConfigurationId = kc.KioskConfigurationId and kcsm.FieldName = 'gmid'
                                    left join KioskConfigurationSetting kcst on kcst.KioskConfigurationId = kc.KioskConfigurationId and kcst.FieldName = 'gtid'
                                    left join KioskConfigurationSetting kcss on kcss.KioskConfigurationId = kc.KioskConfigurationId and kcss.FieldName = 'siteid'
                                    left join KioskConfigurationSetting kcsl on kcsl.KioskConfigurationId = kc.KioskConfigurationId and kcsl.FieldName = 'licenseid'
                                where kc.IsActive = 1

                                update targ
	                                set isoti = isnull(sql.IsOti, 0)
                                from @tbl targ
	                                left join (select 
				                                SerialNumber,
				                                IsOti
			                                from (select serialnumber, isoti, recordedon, row_number() over (partition by serialnumber order by recordedon desc) rn from connectivitytests.dbo.checkopenportresult
			                                where serialnumber like 'vsh%') t
			                                where t.rn = 1) sql on targ.SerialNumber = sql.SerialNumber

                                update targ
                                    set ishd = case when isnull(sql.IntegrationOTIHeartland, '') = 'Enabled' then 1 else 0 end
                                from @tbl targ
                                    left join(select
                                            KioskSerial,
                                            IntegrationsOTIHeartland
                                        from kioskdiags.dbo.kioskstats
                                        where kioskserial like 'vsh%') sql on sql.KioskSerial = targ.SerialNumber

                                select SerialNumber, mid, tid, gmid, gtid, siteid, licenseid, isoti, ishd from @tbl";
                }
                else
                {
                    sql = @"declare @tbl table(SerialNumber varchar(20), mid varchar(100), tid varchar(100), gmid varchar(100), gtid varchar(100), siteid varchar(100), licenseid varchar(100), isoti bit, ishd bit)
                                insert into @tbl(SerialNumber, mid, tid, gmid, gtid, siteid, licenseid)
                                select
                                    k.SerialNumber,
	                                m.mid,
	                                t.tid,
	                                isnull(kcsm.FieldValue, '') 'gmid',
	                                isnull(kcst.FieldValue, '') 'gtid',
	                                isnull(kcss.FieldValue, '') 'siteid',
	                                isnull(kcsl.FieldValue, '') 'licenseid'
                                from KioskConfiguration kc
                                    join kiosk k on k.KioskId = kc.KioskId
                                    join mid m on m.midid = kc.MidId
                                    join tid t on t.tidid = kc.TidId
                                    left
                                join KioskConfigurationSetting kcsm on kcsm.KioskConfigurationId = kc.KioskConfigurationId and kcsm.FieldName = 'gmid'
                                    left join KioskConfigurationSetting kcst on kcst.KioskConfigurationId = kc.KioskConfigurationId and kcst.FieldName = 'gtid'
                                    left join KioskConfigurationSetting kcss on kcss.KioskConfigurationId = kc.KioskConfigurationId and kcss.FieldName = 'siteid'
                                    left join KioskConfigurationSetting kcsl on kcsl.KioskConfigurationId = kc.KioskConfigurationId and kcsl.FieldName = 'licenseid'
                                where kc.IsActive = 1

                                update targ
                                    set isoti = isnull(sql.IsOti, 0)
                                from @tbl targ
                                    left join (select
                                                SerialNumber,
				                                IsOti
                                            from(select serialnumber, isoti, recordedon, row_number() over(partition by serialnumber order by recordedon desc) rn from connectivitytests.dbo.checkopenportresult
                                            where serialnumber like 'vsh%') t
                                            where t.rn = 1) sql on targ.SerialNumber = sql.SerialNumber

                                update targ
	                                set ishd = case when sql.IntegrationOTIHeartland = 'Enabled' then 1 else 0 end
                                from @tbl targ
	                                left join (select
	                                isnull(k.serialnumber, l.serialnumber) as SerialNumber,
	                                case when isnull(i.id, '') = '' then '' else 'Enabled' end as IntegrationOTIHeartland
                                from @tbl src
	                                join customers.dbo.kiosks k on k.SerialNumber collate Latin1_General_CI_AI = src.SerialNumber
	                                join customers.dbo.locations l on k.customerid = l.customerid and k.locationid = l.locationid
	                                join integrations.dbo.stores s on l.groupuniqueid = s.storeid and l.locationactive = 1
	                                left join integrations.dbo.integrations i on i.id = s.IntegrationId and i.IsActive = 1 and i.Integration = 'CBABFEA3-983C-493A-AC28-D2AC4DD1BABC') sql on sql.SerialNumber collate Latin1_General_CI_AI = targ.SerialNumber

                                select SerialNumber, mid, tid, gmid, gtid, siteid, licenseid, isoti, ishd from @tbl";
                }
                SqlCommand cmd = new SqlCommand(sql, apps);
                cmd.CommandTimeout = 300;
                apps.Open();
                SqlDataReader sdr = cmd.ExecuteReader();
                while (sdr.Read())
                {
                    if (sdr[1].ToString().Length == 0 || sdr[2].ToString().Length == 0)
                    {
                        continue;
                    }
                    if (!Convert.ToBoolean(sdr[8].ToString()) && !Convert.ToBoolean(sdr[7].ToString()))
                    {
                        continue;
                    }
                    Credentials NewCred = new Credentials();
                    NewCred.SerialNumber = sdr[0].ToString();
                    if (Convert.ToBoolean(sdr[8].ToString()))
                    {
                        NewCred.MID = EncryptData(sdr[1].ToString());
                        NewCred.TID = EncryptData(sdr[2].ToString());
                    }
                    else
                    {
                        NewCred.MID = EncryptData(sdr[3].ToString());
                        NewCred.TID = EncryptData(sdr[4].ToString());
                    }
                    NewCred.SiteId = sdr[5].ToString();
                    NewCred.LicenseId = sdr[6].ToString();
                    NewCred.IsOti = Convert.ToBoolean(sdr[7].ToString());
                    NewCred.IsHD = Convert.ToBoolean(sdr[8].ToString());
                    ActiveCreds.Add(NewCred);
                }

            }
        }

        static string EncryptData(string Source)
        {
            string Response = string.Empty;
            if (!String.IsNullOrEmpty(EncryptionKey) && !String.IsNullOrEmpty(InitVector))
            {
                security = new Aes256();
                byte[] key = System.Text.Encoding.ASCII.GetBytes(EncryptionKey);
                byte[] iv = System.Text.Encoding.ASCII.GetBytes(InitVector);

                Response = Convert.ToBase64String(security.EncryptStringToBytes_Aes(Source, key, iv));
            }
            return Response;
        }

        public class UsatParams
        {
            public string SerialNumber { get; set; }
            public string Mid { get; set; }
            public string Tid { get; set; }
            public string SiteId { get; set; }
            public string LicenseId { get; set; }
        }

        public class Credentials
        {
            public string SerialNumber { get; set; }
            public string MID { get; set; }
            public string TID { get; set; }
            public bool IsOti { get; set; }
            public bool IsHD { get; set; }
            public string SiteId { get; set; }
            public string LicenseId { get; set; }

            public Credentials()
            {
                SerialNumber = string.Empty;
                MID = string.Empty;
                TID = string.Empty;
                IsOti = false;
                IsHD = false;
            }
        }
    }
}
