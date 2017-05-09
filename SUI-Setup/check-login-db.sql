if exists(select 1 from sysobjects where name = 'webpages_OAuthMembership' and xtype='U') begin
  RAISERROR ('
****************************************** Database Auth already exists. Uncheck "Create DB" in setup. *******************************************',
           18, -- Severity,
           1, -- State,
           N'Database already created'); -- First argument supplies the string.
  return;
end