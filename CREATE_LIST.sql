
CREATE TABLE [dbo].[list](
    [ID] INT IDENTITY(1,1) PRIMARY KEY CLUSTERED,  -- 自增主键
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

-- 添加唯一约束（CodeNo 列唯一）
ALTER TABLE [dbo].[list]
ADD CONSTRAINT UQ_list_CodeNo UNIQUE NONCLUSTERED (CodeNo);
GO