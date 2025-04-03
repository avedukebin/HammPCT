
CREATE TABLE [dbo].[list](
    [ID] INT IDENTITY(1,1) PRIMARY KEY CLUSTERED,  -- ��������
    [Chapter] NVARCHAR(50) NULL,
    [ProductType] NVARCHAR(50) NULL,
    [KDCode] NVARCHAR(20) NULL,
    [CodeNo] NVARCHAR(20) NULL,
    [UnitPrice_EUR] DECIMAL(18,2) NULL,
	[GreenPrice_CNY] DECIMAL(18,2) NULL,
	[SUC_CNY] DECIMAL(18,2) NULL,
	[UnitListPrice_CNY] DECIMAL(18,2) NULL
);
GO

-- ���ΨһԼ����CodeNo ��Ψһ��
ALTER TABLE [dbo].[list]
ADD CONSTRAINT UQ_list_CodeNo UNIQUE NONCLUSTERED (CodeNo);
GO