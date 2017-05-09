if exists(select 1 from sysobjects where name = 'TimeOffGroup' and xtype='U') begin
  RAISERROR ('
***************************************** Database TimeGuard already exists. Uncheck "Create DB" in setup. *******************************************',
           18, -- Severity,
           1, -- State,
           N'Database already created'); -- First argument supplies the string.
  return;
end
