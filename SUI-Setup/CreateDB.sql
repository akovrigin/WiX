/****** Object:  Table [dbo].[Version]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Version](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Number] [nvarchar](max) NULL,
	[ReleaseDate] [datetime] NOT NULL,
	[SoftwareKindId] [int] NOT NULL,
	[MsiLocation] [nvarchar](max) NULL,
	[IsCritical] [int] NOT NULL,
 CONSTRAINT [PK_dbo.Version] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UserSettings]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UserSettings](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[UserId] [bigint] NOT NULL,
	[Section] [nvarchar](max) NULL,
	[Parameter] [nvarchar](max) NULL,
	[Value] [nvarchar](max) NULL,
	[UserName] [nvarchar](max) NULL,
 CONSTRAINT [PK_dbo.UserSettings] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[License]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[License](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[ParentId] [bigint] NULL,
	[Active] [int] NOT NULL,
	[Number] [nvarchar](255) NULL,
	[KeyHash] [nvarchar](512) NULL,
	[ExpirationDate] [datetime] NOT NULL,
	[LicenseTypeId] [int] NOT NULL,
	[Address] [nvarchar](255) NULL,
 CONSTRAINT [PK_dbo.License] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[App]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[App](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Identifier] [int] NULL,
	[Name] [nvarchar](max) NULL,
 CONSTRAINT [PK_dbo.App] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QuestionLanguage]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QuestionLanguage](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Name] [nvarchar](50) NULL,
	[Localization] [nvarchar](5) NULL,
	[EnglishName] [nvarchar](50) NULL,
	[Description] [nvarchar](255) NULL,
 CONSTRAINT [PK_dbo.QuestionLanguage] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Patch]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Patch](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[PatchKey] [nvarchar](max) NULL,
	[ExecuteMode] [int] NOT NULL,
 CONSTRAINT [PK_dbo.Patch] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TechnicalUser]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TechnicalUser](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[OuterUserId] [bigint] NOT NULL,
	[ServerLicenseNumber] [nvarchar](29) NULL,
 CONSTRAINT [PK_dbo.TechnicalUser] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SoftwareGroup]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SoftwareGroup](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[LicenseId] [bigint] NULL,
	[Name] [nvarchar](1024) NULL,
 CONSTRAINT [PK_dbo.SoftwareGroup] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CurrentInactivity]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CurrentInactivity](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[LicenseId] [bigint] NOT NULL,
	[StopTill] [datetime] NOT NULL,
 CONSTRAINT [PK_dbo.CurrentInactivity] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QuestionSet]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QuestionSet](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[QuestionLanguageId] [bigint] NOT NULL,
	[Name] [nvarchar](255) NULL,
	[License_Id] [bigint] NULL,
 CONSTRAINT [PK_dbo.QuestionSet] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReleaseNote]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleaseNote](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Content] [nvarchar](max) NULL,
	[LocaleId] [int] NOT NULL,
	[VersionId] [bigint] NOT NULL,
 CONSTRAINT [PK_dbo.ReleaseNote] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LicenseProperty]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LicenseProperty](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[LicenseId] [bigint] NULL,
	[TypeId] [int] NULL,
	[Value] [nvarchar](4000) NULL,
 CONSTRAINT [PK_dbo.LicenseProperty] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[User]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[User](
	[Id] [bigint] NOT NULL,
	[BaseHour] [int] NULL,
	[WorkDayLen] [int] NULL,
	[TimeShift] [int] NULL,
	[Name] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[QuestionFrequency] [int] NULL,
	[QuestionId] [bigint] NULL,
	[TimeToSend] [datetime] NULL,
 CONSTRAINT [PK_dbo.User] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TimeOffGroup]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TimeOffGroup](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[TypeId] [int] NOT NULL,
	[Name] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[Localization] [nvarchar](max) NULL,
	[ServerLicenseId] [bigint] NULL,
 CONSTRAINT [PK_dbo.TimeOffGroup] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TimeOff]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TimeOff](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[ParentId] [bigint] NULL,
	[Num] [int] NOT NULL,
	[IntervalKind] [int] NOT NULL,
	[Duration] [int] NOT NULL,
	[IsRegular] [bit] NOT NULL,
	[Additional] [int] NULL,
	[TimeOffGroupId] [bigint] NOT NULL,
 CONSTRAINT [PK_dbo.TimeOff] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Question]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Question](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[QuestionSetId] [bigint] NULL,
	[Content] [nvarchar](1024) NULL,
	[QuestionType] [int] NOT NULL,
	[CorrectAnswer] [nvarchar](255) NULL,
	[WrongAnswer] [nvarchar](255) NULL,
 CONSTRAINT [PK_dbo.Question] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Answer]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Answer](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Timestamp] [timestamp] NOT NULL,
	[UserId] [bigint] NOT NULL,
	[QuestionId] [bigint] NOT NULL,
	[Content] [nvarchar](255) NULL,
	[QuestionDate] [datetime] NOT NULL,
	[AnswerDate] [datetime] NOT NULL,
 CONSTRAINT [PK_dbo.Answer] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Activity]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Activity](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[Timestamp] [timestamp] NOT NULL,
	[UserId] [bigint] NOT NULL,
	[Dt] [datetime] NOT NULL,
	[WindowCaption] [nvarchar](320) NULL,
	[ModuleName] [nvarchar](260) NULL,
	[HasInput] [int] NOT NULL,
 CONSTRAINT [PK_dbo.Activity] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SchedLink]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SchedLink](
	[ParentId] [bigint] NOT NULL,
	[ChildId] [bigint] NOT NULL,
 CONSTRAINT [PK_dbo.SchedLink] PRIMARY KEY CLUSTERED 
(
	[ParentId] ASC,
	[ChildId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RequestQueue]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RequestQueue](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[UserId] [bigint] NOT NULL,
	[ReqType] [int] NOT NULL,
	[Tts] [datetime] NOT NULL,
	[Info] [nvarchar](max) NULL,
	[Sent] [bit] NOT NULL,
	[Timestamp] [timestamp] NOT NULL,
 CONSTRAINT [PK_dbo.RequestQueue] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QuestionSetLink]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QuestionSetLink](
	[ParentId] [bigint] NOT NULL,
	[ChildId] [bigint] NOT NULL,
 CONSTRAINT [PK_dbo.QuestionSetLink] PRIMARY KEY CLUSTERED 
(
	[ParentId] ASC,
	[ChildId] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SoftwareGroupCondition]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SoftwareGroupCondition](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[SoftwareGroupId] [bigint] NOT NULL,
	[Name] [nvarchar](1024) NULL,
	[WindowCaptionOption] [int] NOT NULL,
	[WindowCaptionSubstring] [nvarchar](1024) NULL,
	[ModuleNameOption] [int] NOT NULL,
	[ModuleNameSubstring] [nvarchar](1024) NULL,
 CONSTRAINT [PK_dbo.SoftwareGroupCondition] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SoftwarePackage]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SoftwarePackage](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[UserId] [bigint] NOT NULL,
	[Name] [nvarchar](max) NULL,
	[Publisher] [nvarchar](max) NULL,
	[InstalledOn] [datetime] NOT NULL,
	[Version] [nvarchar](max) NULL,
	[SnapshotDate] [datetime] NOT NULL,
	[IsInitial] [int] NOT NULL,
	[RequestId] [bigint] NULL,
 CONSTRAINT [PK_dbo.SoftwarePackage] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Screenshot]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Screenshot](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[UserId] [bigint] NOT NULL,
	[Bits] [varbinary](max) NULL,
	[ShotDt] [datetime] NOT NULL,
	[RequestId] [bigint] NOT NULL,
	[User_Id] [bigint] NULL,
	[Preview] [varbinary](max) NULL,
 CONSTRAINT [PK_dbo.Screenshot] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[Hardware]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Hardware](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[UserId] [bigint] NOT NULL,
	[HwType] [int] NOT NULL,
	[DefaultProperty] [nvarchar](max) NULL,
	[SnapshotDate] [datetime] NOT NULL,
	[IsInitial] [int] NOT NULL,
	[Hash] [nvarchar](68) NULL,
	[RequestId] [bigint] NULL,
	[Discriminator] [nvarchar](128) NOT NULL,
 CONSTRAINT [PK_dbo.Hardware] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HardwareItem]    Script Date: 05/10/2013 17:59:27 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HardwareItem](
	[Id] [bigint] IDENTITY(1,1) NOT NULL,
	[HwId] [bigint] NOT NULL,
	[Hwp] [int] NOT NULL,
	[Val] [nvarchar](max) NULL,
 CONSTRAINT [PK_dbo.HardwareItem] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  ForeignKey [FK_dbo.Activity_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Activity]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Activity_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Activity] CHECK CONSTRAINT [FK_dbo.Activity_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.Answer_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Answer]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Answer_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Answer] CHECK CONSTRAINT [FK_dbo.Answer_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.CurrentInactivity_dbo.License_LicenseId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[CurrentInactivity]  WITH CHECK ADD  CONSTRAINT [FK_dbo.CurrentInactivity_dbo.License_LicenseId] FOREIGN KEY([LicenseId])
REFERENCES [dbo].[License] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[CurrentInactivity] CHECK CONSTRAINT [FK_dbo.CurrentInactivity_dbo.License_LicenseId]
GO
/****** Object:  ForeignKey [FK_dbo.Hardware_dbo.RequestQueue_RequestId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Hardware]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Hardware_dbo.RequestQueue_RequestId] FOREIGN KEY([RequestId])
REFERENCES [dbo].[RequestQueue] ([Id])
GO
ALTER TABLE [dbo].[Hardware] CHECK CONSTRAINT [FK_dbo.Hardware_dbo.RequestQueue_RequestId]
GO
/****** Object:  ForeignKey [FK_dbo.Hardware_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Hardware]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Hardware_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Hardware] CHECK CONSTRAINT [FK_dbo.Hardware_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.HardwareItem_dbo.Hardware_HwId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[HardwareItem]  WITH CHECK ADD  CONSTRAINT [FK_dbo.HardwareItem_dbo.Hardware_HwId] FOREIGN KEY([HwId])
REFERENCES [dbo].[Hardware] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[HardwareItem] CHECK CONSTRAINT [FK_dbo.HardwareItem_dbo.Hardware_HwId]
GO
/****** Object:  ForeignKey [FK_dbo.License_dbo.License_ParentId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[License]  WITH CHECK ADD  CONSTRAINT [FK_dbo.License_dbo.License_ParentId] FOREIGN KEY([ParentId])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[License] CHECK CONSTRAINT [FK_dbo.License_dbo.License_ParentId]
GO
/****** Object:  ForeignKey [FK_dbo.LicenseProperty_dbo.License_LicenseId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[LicenseProperty]  WITH CHECK ADD  CONSTRAINT [FK_dbo.LicenseProperty_dbo.License_LicenseId] FOREIGN KEY([LicenseId])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[LicenseProperty] CHECK CONSTRAINT [FK_dbo.LicenseProperty_dbo.License_LicenseId]
GO
/****** Object:  ForeignKey [FK_dbo.Question_dbo.QuestionSet_QuestionSetId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Question]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Question_dbo.QuestionSet_QuestionSetId] FOREIGN KEY([QuestionSetId])
REFERENCES [dbo].[QuestionSet] ([Id])
GO
ALTER TABLE [dbo].[Question] CHECK CONSTRAINT [FK_dbo.Question_dbo.QuestionSet_QuestionSetId]
GO
/****** Object:  ForeignKey [FK_dbo.QuestionSet_dbo.License_License_Id]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[QuestionSet]  WITH CHECK ADD  CONSTRAINT [FK_dbo.QuestionSet_dbo.License_License_Id] FOREIGN KEY([License_Id])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[QuestionSet] CHECK CONSTRAINT [FK_dbo.QuestionSet_dbo.License_License_Id]
GO
/****** Object:  ForeignKey [FK_dbo.QuestionSet_dbo.QuestionLanguage_QuestionLanguageId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[QuestionSet]  WITH CHECK ADD  CONSTRAINT [FK_dbo.QuestionSet_dbo.QuestionLanguage_QuestionLanguageId] FOREIGN KEY([QuestionLanguageId])
REFERENCES [dbo].[QuestionLanguage] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[QuestionSet] CHECK CONSTRAINT [FK_dbo.QuestionSet_dbo.QuestionLanguage_QuestionLanguageId]
GO
/****** Object:  ForeignKey [FK_dbo.QuestionSetLink_dbo.QuestionSet_ParentId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[QuestionSetLink]  WITH CHECK ADD  CONSTRAINT [FK_dbo.QuestionSetLink_dbo.QuestionSet_ParentId] FOREIGN KEY([ParentId])
REFERENCES [dbo].[QuestionSet] ([Id])
GO
ALTER TABLE [dbo].[QuestionSetLink] CHECK CONSTRAINT [FK_dbo.QuestionSetLink_dbo.QuestionSet_ParentId]
GO
/****** Object:  ForeignKey [FK_dbo.QuestionSetLink_dbo.User_ChildId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[QuestionSetLink]  WITH CHECK ADD  CONSTRAINT [FK_dbo.QuestionSetLink_dbo.User_ChildId] FOREIGN KEY([ChildId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[QuestionSetLink] CHECK CONSTRAINT [FK_dbo.QuestionSetLink_dbo.User_ChildId]
GO
/****** Object:  ForeignKey [FK_dbo.ReleaseNote_dbo.Version_VersionId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[ReleaseNote]  WITH CHECK ADD  CONSTRAINT [FK_dbo.ReleaseNote_dbo.Version_VersionId] FOREIGN KEY([VersionId])
REFERENCES [dbo].[Version] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[ReleaseNote] CHECK CONSTRAINT [FK_dbo.ReleaseNote_dbo.Version_VersionId]
GO
/****** Object:  ForeignKey [FK_dbo.RequestQueue_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[RequestQueue]  WITH CHECK ADD  CONSTRAINT [FK_dbo.RequestQueue_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[RequestQueue] CHECK CONSTRAINT [FK_dbo.RequestQueue_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.SchedLink_dbo.TimeOffGroup_ParentId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SchedLink]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SchedLink_dbo.TimeOffGroup_ParentId] FOREIGN KEY([ParentId])
REFERENCES [dbo].[TimeOffGroup] ([Id])
GO
ALTER TABLE [dbo].[SchedLink] CHECK CONSTRAINT [FK_dbo.SchedLink_dbo.TimeOffGroup_ParentId]
GO
/****** Object:  ForeignKey [FK_dbo.SchedLink_dbo.User_ChildId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SchedLink]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SchedLink_dbo.User_ChildId] FOREIGN KEY([ChildId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[SchedLink] CHECK CONSTRAINT [FK_dbo.SchedLink_dbo.User_ChildId]
GO
/****** Object:  ForeignKey [FK_dbo.Screenshot_dbo.RequestQueue_RequestId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Screenshot]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Screenshot_dbo.RequestQueue_RequestId] FOREIGN KEY([RequestId])
REFERENCES [dbo].[RequestQueue] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[Screenshot] CHECK CONSTRAINT [FK_dbo.Screenshot_dbo.RequestQueue_RequestId]
GO
/****** Object:  ForeignKey [FK_dbo.Screenshot_dbo.User_User_Id]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Screenshot]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Screenshot_dbo.User_User_Id] FOREIGN KEY([User_Id])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Screenshot] CHECK CONSTRAINT [FK_dbo.Screenshot_dbo.User_User_Id]
GO
/****** Object:  ForeignKey [FK_dbo.Screenshot_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[Screenshot]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Screenshot_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Screenshot] CHECK CONSTRAINT [FK_dbo.Screenshot_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.SoftwareGroup_dbo.License_LicenseId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SoftwareGroup]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SoftwareGroup_dbo.License_LicenseId] FOREIGN KEY([LicenseId])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[SoftwareGroup] CHECK CONSTRAINT [FK_dbo.SoftwareGroup_dbo.License_LicenseId]
GO
/****** Object:  ForeignKey [FK_dbo.SoftwareGroupCondition_dbo.SoftwareGroup_SoftwareGroupId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SoftwareGroupCondition]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SoftwareGroupCondition_dbo.SoftwareGroup_SoftwareGroupId] FOREIGN KEY([SoftwareGroupId])
REFERENCES [dbo].[SoftwareGroup] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[SoftwareGroupCondition] CHECK CONSTRAINT [FK_dbo.SoftwareGroupCondition_dbo.SoftwareGroup_SoftwareGroupId]
GO
/****** Object:  ForeignKey [FK_dbo.SoftwarePackage_dbo.RequestQueue_RequestId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SoftwarePackage]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SoftwarePackage_dbo.RequestQueue_RequestId] FOREIGN KEY([RequestId])
REFERENCES [dbo].[RequestQueue] ([Id])
GO
ALTER TABLE [dbo].[SoftwarePackage] CHECK CONSTRAINT [FK_dbo.SoftwarePackage_dbo.RequestQueue_RequestId]
GO
/****** Object:  ForeignKey [FK_dbo.SoftwarePackage_dbo.User_UserId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[SoftwarePackage]  WITH CHECK ADD  CONSTRAINT [FK_dbo.SoftwarePackage_dbo.User_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[SoftwarePackage] CHECK CONSTRAINT [FK_dbo.SoftwarePackage_dbo.User_UserId]
GO
/****** Object:  ForeignKey [FK_dbo.TimeOff_dbo.TimeOff_ParentId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[TimeOff]  WITH CHECK ADD  CONSTRAINT [FK_dbo.TimeOff_dbo.TimeOff_ParentId] FOREIGN KEY([ParentId])
REFERENCES [dbo].[TimeOff] ([Id])
GO
ALTER TABLE [dbo].[TimeOff] CHECK CONSTRAINT [FK_dbo.TimeOff_dbo.TimeOff_ParentId]
GO
/****** Object:  ForeignKey [FK_dbo.TimeOff_dbo.TimeOffGroup_TimeOffGroupId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[TimeOff]  WITH CHECK ADD  CONSTRAINT [FK_dbo.TimeOff_dbo.TimeOffGroup_TimeOffGroupId] FOREIGN KEY([TimeOffGroupId])
REFERENCES [dbo].[TimeOffGroup] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[TimeOff] CHECK CONSTRAINT [FK_dbo.TimeOff_dbo.TimeOffGroup_TimeOffGroupId]
GO
/****** Object:  ForeignKey [FK_dbo.TimeOffGroup_dbo.License_ServerLicenseId]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[TimeOffGroup]  WITH CHECK ADD  CONSTRAINT [FK_dbo.TimeOffGroup_dbo.License_ServerLicenseId] FOREIGN KEY([ServerLicenseId])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[TimeOffGroup] CHECK CONSTRAINT [FK_dbo.TimeOffGroup_dbo.License_ServerLicenseId]
GO
/****** Object:  ForeignKey [FK_dbo.User_dbo.License_Id]    Script Date: 05/10/2013 17:59:27 ******/
ALTER TABLE [dbo].[User]  WITH CHECK ADD  CONSTRAINT [FK_dbo.User_dbo.License_Id] FOREIGN KEY([Id])
REFERENCES [dbo].[License] ([Id])
GO
ALTER TABLE [dbo].[User] CHECK CONSTRAINT [FK_dbo.User_dbo.License_Id]
GO
