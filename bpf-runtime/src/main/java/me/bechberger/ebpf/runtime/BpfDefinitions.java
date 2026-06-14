/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with bpf
 */
@java.lang.SuppressWarnings("unused")
public final class BpfDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_address_lookup(@Unsigned long addr, Ptr<java.lang. @Unsigned Long> size,
      Ptr<java.lang. @Unsigned Long> off, String sym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_arch_text_poke(Ptr<?> ip, bpf_text_poke_type t, Ptr<?> old_addr,
      Ptr<?> new_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_array_map_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_async_init(Ptr<bpf_async_kern> async, Ptr<bpf_map> map,
      @Unsigned long flags, bpf_async_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_call_base(@Unsigned long r1, @Unsigned long r2,
      @Unsigned long r3, @Unsigned long r4, @Unsigned long r5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_core_types_are_compat((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4, $arg5)")
  public static int __bpf_core_types_are_compat(Ptr<btf> local_btf, @Unsigned int local_id,
      Ptr<btf> targ_btf, @Unsigned int targ_id, int level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_core_types_match((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4, $arg5, $arg6)")
  public static int __bpf_core_types_match(Ptr<btf> local_btf, @Unsigned int local_id,
      Ptr<btf> targ_btf, @Unsigned int targ_id, boolean behind_ptr, int level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)__bpf_dynptr_data((const struct bpf_dynptr_kern*)$arg1, $arg2))")
  public static Ptr<?> __bpf_dynptr_data(Ptr<bpf_dynptr_kern> ptr, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_dynptr_data_rw((const struct bpf_dynptr_kern*)$arg1, $arg2)")
  public static Ptr<?> __bpf_dynptr_data_rw(Ptr<bpf_dynptr_kern> ptr, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_dynptr_is_rdonly((const struct bpf_dynptr_kern*)$arg1)")
  public static boolean __bpf_dynptr_is_rdonly(Ptr<bpf_dynptr_kern> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_dynptr_read($arg1, $arg2, (const struct bpf_dynptr_kern*)$arg3, $arg4, $arg5)")
  public static int __bpf_dynptr_read(Ptr<?> dst, @Unsigned int len, Ptr<bpf_dynptr_kern> src,
      @Unsigned int offset, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_dynptr_size((const struct bpf_dynptr_kern*)$arg1)")
  public static @Unsigned int __bpf_dynptr_size(Ptr<bpf_dynptr_kern> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_dynptr_write((const struct bpf_dynptr_kern*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int __bpf_dynptr_write(Ptr<bpf_dynptr_kern> dst, @Unsigned int offset, Ptr<?> src,
      @Unsigned int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_event_entry_free(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_free_used_btfs(Ptr<btf_mod_pair> used_btfs, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_free_used_maps(Ptr<bpf_prog_aux> aux, Ptr<Ptr<bpf_map>> used_maps,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __bpf_get_stack(Ptr<pt_regs> regs, Ptr<task_struct> task,
      Ptr<perf_callchain_entry> trace_in, Ptr<?> buf, @Unsigned int size, @Unsigned long flags,
      boolean may_fault) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __bpf_get_stackid(Ptr<bpf_map> map, Ptr<perf_callchain_entry> trace,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long __bpf_get_task_stack(Ptr<task_struct> task, Ptr<?> buf, @Unsigned int size,
      @Unsigned long flags, boolean may_fault) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_getsockopt(Ptr<sock> sk, int level, int optname, String optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_hash_map_seq_show(Ptr<seq_file> seq, Ptr<htab_elem> elem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_local_storage_free_trace_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_local_storage_insert_cache(Ptr<bpf_local_storage> local_storage,
      Ptr<bpf_local_storage_map> smap, Ptr<bpf_local_storage_elem> selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_lru_list_rotate_active(Ptr<bpf_lru> lru, Ptr<bpf_lru_list> l) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_lru_list_rotate_inactive(Ptr<bpf_lru> lru, Ptr<bpf_lru_list> l) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int __bpf_lru_list_shrink(Ptr<bpf_lru> lru, Ptr<bpf_lru_list> l,
      @Unsigned int tgt_nshrink, Ptr<list_head> free_list, bpf_lru_list_type tgt_free_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_lru_node_move(Ptr<bpf_lru_list> l, Ptr<bpf_lru_node> node,
      bpf_lru_list_type tgt_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_lru_node_move_to_free(Ptr<bpf_lru_list> l, Ptr<bpf_lru_node> node,
      Ptr<list_head> free_list, bpf_lru_list_type tgt_free_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __bpf_map_area_alloc(@Unsigned long size, int numa_node, boolean mmapable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> __bpf_map_inc_not_zero(Ptr<bpf_map> map, boolean uref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_obj_drop_impl($arg1, (const struct btf_record*)$arg2, $arg3)")
  public static void __bpf_obj_drop_impl(Ptr<?> p, Ptr<btf_record> rec, boolean percpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __bpf_offload_dev_match(Ptr<bpf_prog> prog, Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_offload_dev_netdev_register(Ptr<bpf_offload_dev> offdev,
      Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_offload_dev_netdev_unregister(Ptr<bpf_offload_dev> offdev,
      Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_array_free_sleepable_cb(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_prog_dev_bound_init(Ptr<bpf_prog> prog, Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_prog_enter(Ptr<bpf_prog> prog,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_prog_enter_lsm_cgroup(Ptr<bpf_prog> prog,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_prog_enter_recur(Ptr<bpf_prog> prog,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_prog_enter_sleepable(Ptr<bpf_prog> prog,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __bpf_prog_enter_sleepable_recur(Ptr<bpf_prog> prog,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_exit(Ptr<bpf_prog> prog, @Unsigned long start,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_exit_lsm_cgroup(Ptr<bpf_prog> prog, @Unsigned long start,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_exit_recur(Ptr<bpf_prog> prog, @Unsigned long start,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_exit_sleepable(Ptr<bpf_prog> prog, @Unsigned long start,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_exit_sleepable_recur(Ptr<bpf_prog> prog, @Unsigned long start,
      Ptr<bpf_tramp_run_ctx> run_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_free(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> __bpf_prog_get(@Unsigned int ufd, Ptr<bpf_prog_type> attach_type,
      boolean attach_drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_prog_map_compatible($arg1, (const struct bpf_prog*)$arg2)")
  public static boolean __bpf_prog_map_compatible(Ptr<bpf_map> map, Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_offload_destroy(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_put(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_put_noref(Ptr<bpf_prog> prog, boolean deferred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_put_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_prog_ret0_warn((const void*)$arg1, (const struct bpf_insn*)$arg2)")
  public static @Unsigned int __bpf_prog_ret0_warn(Ptr<?> ctx, Ptr<bpf_insn> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_prog_ret1((const void*)$arg1, (const struct bpf_insn*)$arg2)")
  public static @Unsigned int __bpf_prog_ret1(Ptr<?> ctx, Ptr<bpf_insn> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_prog_run_save_cb((const struct bpf_prog*)$arg1, (const void*)$arg2)")
  public static @Unsigned int __bpf_prog_run_save_cb(Ptr<bpf_prog> prog, Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_prog_test_run_raw_tp(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_redirect(Ptr<sk_buff> skb, Ptr<net_device> dev, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_redirect_neigh(Ptr<sk_buff> skb, Ptr<net_device> dev,
      Ptr<bpf_nh_params> nh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_redirect_no_mac(Ptr<sk_buff> skb, Ptr<net_device> dev,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> __bpf_ringbuf_reserve(Ptr<bpf_ringbuf> rb, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_selem_free_trace_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_setsockopt(Ptr<sock> sk, int level, int optname, String optval,
      int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> __bpf_sk_lookup(Ptr<sk_buff> skb, Ptr<bpf_sock_tuple> tuple,
      @Unsigned int len, Ptr<net> caller_net, @Unsigned int ifindex, char proto,
      @Unsigned long netns_id, @Unsigned long flags, int sdif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_sk_storage_map_seq_show(Ptr<seq_file> seq,
      Ptr<bpf_local_storage_elem> selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_skb_change_tail(Ptr<sk_buff> skb, @Unsigned int new_len,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_skb_load_bytes((const struct sk_buff*)$arg1, $arg2, $arg3, $arg4)")
  public static int __bpf_skb_load_bytes(Ptr<sk_buff> skb, @Unsigned int offset, Ptr<?> to,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_skb_store_bytes($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static int __bpf_skb_store_bytes(Ptr<sk_buff> skb, @Unsigned int offset, Ptr<?> from,
      @Unsigned int len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> __bpf_skc_lookup(Ptr<sk_buff> skb, Ptr<bpf_sock_tuple> tuple,
      @Unsigned int len, Ptr<net> caller_net, @Unsigned int ifindex, char proto,
      @Unsigned long netns_id, @Unsigned long flags, int sdif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_spin_lock_irqsave(Ptr<bpf_spin_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_spin_unlock_irqrestore(Ptr<bpf_spin_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_stream_push_str($arg1, (const u8*)$arg2, $arg3)")
  public static int __bpf_stream_push_str(Ptr<llist_head> log, String str, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_strtoull((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int __bpf_strtoull(String buf, @Unsigned long buf_len, @Unsigned long flags,
      Ptr<java.lang. @Unsigned Long> res,
      Ptr<java.lang. @OriginalName("bool") Boolean> is_negative) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_struct_ops_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tcp_ca_init(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tcp_ca_release(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ack_update_msk(Ptr<?> __data, @Unsigned long data_ack,
      @Unsigned long old_snd_una, @Unsigned long new_snd_una, @Unsigned long new_wnd_end,
      @Unsigned long msk_wnd_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_aer_event($arg1, (const u8*)$arg2, (const unsigned int)$arg3, (const u8)$arg4, (const u8)$arg5, $arg6)")
  public static void __bpf_trace_aer_event(Ptr<?> __data, String dev_name, @Unsigned int status,
      char severity, char tlp_header_valid, Ptr<pcie_tlp_log> tlp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_alarm_class(Ptr<?> __data, Ptr<alarm> alarm,
      @OriginalName("ktime_t") long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_alarmtimer_suspend(Ptr<?> __data,
      @OriginalName("ktime_t") long expires, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_alloc_vmap_area(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long size, @Unsigned long align, @Unsigned long vstart, @Unsigned long vend,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_amd_pstate_epp_perf(Ptr<?> __data, @Unsigned int cpu_id,
      char highest_perf, char epp, char min_perf, char max_perf, boolean boost, boolean changed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_amd_pstate_perf(Ptr<?> __data, char min_perf, char target_perf,
      char capacity, @Unsigned long freq, @Unsigned long mperf, @Unsigned long aperf,
      @Unsigned long tsc, @Unsigned int cpu_id, boolean fast_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_arm_event($arg1, (const struct cper_sec_proc_arm*)$arg2, (const u8*)$arg3, (const unsigned int)$arg4, (const u8*)$arg5, (const unsigned int)$arg6, (const u8*)$arg7, (const unsigned int)$arg8, $arg9, $arg10)")
  public static void __bpf_trace_arm_event(Ptr<?> __data, Ptr<cper_sec_proc_arm> proc,
      Ptr<java.lang.Character> pei_err, @Unsigned int pei_len, Ptr<java.lang.Character> ctx_err,
      @Unsigned int ctx_len, Ptr<java.lang.Character> oem, @Unsigned int oem_len, char sev,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_bmdma_status(Ptr<?> __data, Ptr<ata_port> ap,
      @Unsigned int host_stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_eh_action_template(Ptr<?> __data, Ptr<ata_link> link,
      @Unsigned int devno, @Unsigned int eh_action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_eh_link_autopsy(Ptr<?> __data, Ptr<ata_device> dev,
      @Unsigned int eh_action, @Unsigned int eh_err_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_eh_link_autopsy_qc(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ata_exec_command_template($arg1, $arg2, (const struct ata_taskfile*)$arg3, $arg4)")
  public static void __bpf_trace_ata_exec_command_template(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_link_reset_begin_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_link_reset_end_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_port_eh_begin_template(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_qc_complete_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_qc_issue_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_sff_hsm_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      char status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_sff_template(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ata_tf_load($arg1, $arg2, (const struct ata_taskfile*)$arg3)")
  public static void __bpf_trace_ata_tf_load(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ata_transfer_data_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      @Unsigned int offset, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_balance_dirty_pages(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<dirty_throttle_control> dtc, @Unsigned long dirty_ratelimit,
      @Unsigned long task_ratelimit, @Unsigned long dirtied, @Unsigned long period, long pause,
      @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_bdi_dirty_ratelimit(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned long dirty_rate, @Unsigned long task_ratelimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_blkdev_zone_mgmt(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("sector_t") long nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_bio(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_bio_complete(Ptr<?> __data, Ptr<request_queue> q,
      Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_bio_remap(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_buffer(Ptr<?> __data, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_plug(Ptr<?> __data, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_rq(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_rq_completion(Ptr<?> __data, Ptr<request> rq,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_rq_remap(Ptr<?> __data, Ptr<request> rq,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_rq_requeue(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_split(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned int new_sector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_unplug(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int depth, boolean explicit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_block_zwplug(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int zno, @Unsigned @OriginalName("sector_t") long sector,
      @Unsigned int nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_bpf_test_finish(Ptr<?> __data, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_bpf_trace_printk($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_bpf_trace_printk(Ptr<?> __data, String bpf_string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_bpf_trigger_tp(Ptr<?> __data, int nonce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_bpf_xdp_link_attach_failed($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_bpf_xdp_link_attach_failed(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_br_fdb_add($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static void __bpf_trace_br_fdb_add(Ptr<?> __data, Ptr<ndmsg> ndm, Ptr<net_device> dev,
      String addr, @Unsigned short vid, @Unsigned short nlh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_br_fdb_external_learn_add($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static void __bpf_trace_br_fdb_external_learn_add(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> p, String addr, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_br_fdb_update($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static void __bpf_trace_br_fdb_update(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> source, String addr, @Unsigned short vid, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_br_mdb_full($arg1, (const struct net_device*)$arg2, (const struct br_ip*)$arg3)")
  public static void __bpf_trace_br_mdb_full(Ptr<?> __data, Ptr<net_device> dev, Ptr<br_ip> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cache_tag_flush(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cache_tag_log(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cap_capable($arg1, (const struct cred*)$arg2, $arg3, (const struct user_namespace*)$arg4, $arg5, $arg6)")
  public static void __bpf_trace_cap_capable(Ptr<?> __data, Ptr<cred> cred,
      Ptr<user_namespace> target_ns, Ptr<user_namespace> capable_ns, int cap, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cdev_update(Ptr<?> __data, Ptr<thermal_cooling_device> cdev,
      @Unsigned long target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cgroup($arg1, $arg2, (const u8*)$arg3)")
  public static void __bpf_trace_cgroup(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cgroup_event($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void __bpf_trace_cgroup_event(Ptr<?> __data, Ptr<cgroup> cgrp, String path,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cgroup_migrate($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_cgroup_migrate(Ptr<?> __data, Ptr<cgroup> dst_cgrp, String path,
      Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cgroup_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cgroup_rstat(Ptr<?> __data, Ptr<cgroup> cgrp, int cpu,
      boolean contended) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_duty_cycle(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_parent(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_phase(Ptr<?> __data, Ptr<clk_core> core, int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_rate(Ptr<?> __data, Ptr<clk_core> core, @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_rate_range(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long min, @Unsigned long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_clk_rate_request(Ptr<?> __data, Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cma_alloc_busy_retry($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5, $arg6)")
  public static void __bpf_trace_cma_alloc_busy_retry(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cma_alloc_finish($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5, $arg6, $arg7)")
  public static void __bpf_trace_cma_alloc_finish(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count, @Unsigned int align, int errorno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cma_alloc_start($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_cma_alloc_start(Ptr<?> __data, String name, @Unsigned long count,
      @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cma_release($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5)")
  public static void __bpf_trace_cma_release(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_compact_retry(Ptr<?> __data, int order, compact_priority priority,
      compact_result result, int retries, int max_retries, boolean ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_console($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_console(Ptr<?> __data, String text, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_consume_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_contention_begin(Ptr<?> __data, Ptr<?> lock, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_contention_end(Ptr<?> __data, Ptr<?> lock, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_context_tracking_user(Ptr<?> __data, int dummy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cpu(Ptr<?> __data, @Unsigned int state, @Unsigned int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cpu_frequency_limits(Ptr<?> __data, Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cpu_idle_miss(Ptr<?> __data, @Unsigned int cpu_id,
      @Unsigned int state, boolean below) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cpu_latency_qos_request(Ptr<?> __data, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cpuhp_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int))$arg5)")
  public static void __bpf_trace_cpuhp_enter(Ptr<?> __data, @Unsigned int cpu, int target, int idx,
      Ptr<?> fun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_cpuhp_exit(Ptr<?> __data, @Unsigned int cpu, int state, int idx,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_cpuhp_multi_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int, struct hlist_node*))$arg5, $arg6)")
  public static void __bpf_trace_cpuhp_multi_enter(Ptr<?> __data, @Unsigned int cpu, int target,
      int idx, Ptr<?> fun, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_csd_function(Ptr<?> __data,
      @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_csd_queue_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_csd_queue_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ctime(Ptr<?> __data, Ptr<inode> inode, Ptr<timespec64> ctime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ctime_ns_xchg(Ptr<?> __data, Ptr<inode> inode, @Unsigned int old,
      @Unsigned int _new, @Unsigned int cur) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dax_pmd_fault_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, @Unsigned long max_pgoff, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dax_pmd_load_hole_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, Ptr<folio> zero_folio, Ptr<?> radix_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dax_pte_fault_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dax_writeback_one(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pgoff, @Unsigned long pglen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dax_writeback_range_class(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long start_index, @Unsigned long end_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_dev_pm_qos_request($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_dev_pm_qos_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_devfreq_frequency(Ptr<?> __data, Ptr<devfreq> devfreq,
      @Unsigned long freq, @Unsigned long prev_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_devfreq_monitor(Ptr<?> __data, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_device_pm_callback_end(Ptr<?> __data, Ptr<device> dev, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_device_pm_callback_start($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void __bpf_trace_device_pm_callback_start(Ptr<?> __data, Ptr<device> dev,
      String pm_ops, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_health_recover_aborted($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_devlink_health_recover_aborted(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, boolean health_state, @Unsigned long time_since_last_recover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_health_report($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void __bpf_trace_devlink_health_report(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_health_reporter_state_update($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, $arg4)")
  public static void __bpf_trace_devlink_health_reporter_state_update(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_hwerr($arg1, (const struct devlink*)$arg2, $arg3, (const u8*)$arg4)")
  public static void __bpf_trace_devlink_hwerr(Ptr<?> __data, Ptr<devlink> devlink, int err,
      String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_hwmsg($arg1, (const struct devlink*)$arg2, $arg3, $arg4, (const u8*)$arg5, $arg6)")
  public static void __bpf_trace_devlink_hwmsg(Ptr<?> __data, Ptr<devlink> devlink,
      boolean incoming, @Unsigned long type, Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devlink_trap_report($arg1, (const struct devlink*)$arg2, $arg3, (const struct devlink_trap_metadata*)$arg4)")
  public static void __bpf_trace_devlink_trap_report(Ptr<?> __data, Ptr<devlink> devlink,
      Ptr<sk_buff> skb, Ptr<devlink_trap_metadata> metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_devres($arg1, $arg2, (const u8*)$arg3, $arg4, (const u8*)$arg5, $arg6)")
  public static void __bpf_trace_devres(Ptr<?> __data, Ptr<device> dev, String op, Ptr<?> node,
      String name, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_alloc_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_alloc_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_fence(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_fence_unsignaled(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_free_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_free_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_map(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_map_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, int ents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_map_sg_err(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, int err, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_sync_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_sync_single(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_unmap(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dma_unmap_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_dql_stall_detected(Ptr<?> __data, @Unsigned short thrs,
      @Unsigned int len, @Unsigned long last_reap, @Unsigned long hist_head, @Unsigned long now,
      Ptr<java.lang. @Unsigned Long> hist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_drm_vblank_event(Ptr<?> __data, int crtc, @Unsigned int seq,
      @OriginalName("ktime_t") long time, boolean high_prec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_drm_vblank_event_delivered(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_drm_vblank_event_queued(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_emulate_vsyscall(Ptr<?> __data, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_error_da_monitor_id(Ptr<?> __data, int id, String state,
      String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_error_report_template(Ptr<?> __data, error_detector error_detector,
      @Unsigned long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_event_da_monitor_id(Ptr<?> __data, int id, String state,
      String event, String next_state, boolean final_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_exceptions(Ptr<?> __data, @Unsigned long address,
      Ptr<pt_regs> regs, @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_exit_mmap(Ptr<?> __data, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__es_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__es_shrink_enter(Ptr<?> __data, Ptr<super_block> sb,
      int nr_to_scan, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__fallocate_mode(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__folio_op(Ptr<?> __data, Ptr<inode> inode, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__map_blocks_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk, @Unsigned int len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__map_blocks_exit(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int flags, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__mb_new_pa(Ptr<?> __data, Ptr<ext4_allocation_context> ac,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__mballoc(Ptr<?> __data, Ptr<super_block> sb, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__trim(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__truncate(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__write_begin(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4__write_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_alloc_da_blocks(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_allocate_blocks(Ptr<?> __data,
      Ptr<ext4_allocation_request> ar, @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_allocate_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_begin_ordered_truncate(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long new_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_collapse_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_release_space(Ptr<?> __data, Ptr<inode> inode,
      int freed_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int nr_resv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_update_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int used_blocks, int quota_claim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_write_folios_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_write_folios_start(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_da_write_pages_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_discard_blocks(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long blk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_discard_preallocations(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_drop_inode(Ptr<?> __data, Ptr<inode> inode, int drop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ext4_error($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void __bpf_trace_ext4_error(Ptr<?> __data, Ptr<super_block> sb, String function,
      @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_find_extent_range_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_find_extent_range_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_insert_delayed_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, boolean lclu_allocated, boolean end_allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_lookup_extent_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_lookup_extent_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, int found) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_remove_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_shrink(Ptr<?> __data, Ptr<super_block> sb, int nr_shrunk,
      @Unsigned long scan_time, int nr_skipped, int retried) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_es_shrink_scan_exit(Ptr<?> __data, Ptr<super_block> sb,
      int nr_shrunk, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_evict_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_convert_to_initialized_enter(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_convert_to_initialized_fastpath(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux, Ptr<ext4_extent> ix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_handle_unwritten_extents(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, int flags, @Unsigned int allocated,
      @Unsigned @OriginalName("ext4_fsblk_t") long newblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_load_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_remove_space(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_remove_space_done(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth, Ptr<partial_cluster> pc,
      @Unsigned @OriginalName("__le16") short eh_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_rm_idx(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_rm_leaf(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start, Ptr<ext4_extent> ex,
      Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_ext_show_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, @Unsigned short len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fallocate_exit(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @Unsigned int max_blocks, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_cleanup(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int full,
      @Unsigned @OriginalName("tid_t") int tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_commit_start(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_commit_stop(Ptr<?> __data, Ptr<super_block> sb, int nblks,
      int reason, @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_replay(Ptr<?> __data, Ptr<super_block> sb, int tag,
      int ino, int priv1, int priv2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_replay_scan(Ptr<?> __data, Ptr<super_block> sb, int error,
      int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_stats(Ptr<?> __data, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_track_dentry(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_track_inode(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fc_track_range(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, long start,
      long end, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_forget(Ptr<?> __data, Ptr<inode> inode, int is_metadata,
      @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_free_blocks(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long block, @Unsigned long count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_free_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_fsmap_class(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned int keydev, @Unsigned int agno, @Unsigned long bno, @Unsigned long len,
      @Unsigned long owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_get_implied_cluster_alloc_exit(Ptr<?> __data,
      Ptr<super_block> sb, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_getfsmap_class(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_fsmap> fsmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_insert_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_invalidate_folio_op(Ptr<?> __data, Ptr<folio> folio,
      @Unsigned long offset, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_journal_start_inode(Ptr<?> __data, Ptr<inode> inode,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_journal_start_reserved(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_journal_start_sb(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_lazy_itable_init(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_load_inode(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mark_inode_dirty(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mb_discard_preallocations(Ptr<?> __data, Ptr<super_block> sb,
      int needed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mb_release_group_pa(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mb_release_inode_pa(Ptr<?> __data,
      Ptr<ext4_prealloc_space> pa, @Unsigned long block, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mballoc_alloc(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_mballoc_prealloc(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_nfs_commit_metadata(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_other_inode_update_time(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ino_t") long orig_ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_prefetch_bitmaps(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group,
      @Unsigned @OriginalName("ext4_group_t") int next, @Unsigned int prefetch_ios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_read_block_bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group, boolean prefetch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_remove_blocks(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_extent> ex, @Unsigned @OriginalName("ext4_lblk_t") int from,
      @Unsigned @OriginalName("ext4_fsblk_t") long to, Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_request_blocks(Ptr<?> __data,
      Ptr<ext4_allocation_request> ar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_request_inode(Ptr<?> __data, Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_shutdown(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_sync_file_enter(Ptr<?> __data, Ptr<file> file, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_sync_file_exit(Ptr<?> __data, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_sync_fs(Ptr<?> __data, Ptr<super_block> sb, int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_unlink_enter(Ptr<?> __data, Ptr<inode> parent,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_unlink_exit(Ptr<?> __data, Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_update_sb(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long fsblk, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_writepages(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ext4_writepages_result(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, int ret, int pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_extlog_mem_event($arg1, $arg2, $arg3, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg4, (const u8*)$arg5, $arg6)")
  public static void __bpf_trace_extlog_mem_event(Ptr<?> __data, Ptr<cper_sec_mem_err> mem,
      @Unsigned int err_seq, Ptr<@OriginalName("guid_t") uuid_t> fru_id, String fru_text,
      char sev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_fdb_delete(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_fdb_entry> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_fib6_table_lookup($arg1, (const struct net*)$arg2, (const struct fib6_result*)$arg3, $arg4, (const struct flowi6*)$arg5)")
  public static void __bpf_trace_fib6_table_lookup(Ptr<?> __data, Ptr<net> net,
      Ptr<fib6_result> res, Ptr<fib6_table> table, Ptr<flowi6> flp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_fib_table_lookup($arg1, $arg2, (const struct flowi4*)$arg3, (const struct fib_nh_common*)$arg4, $arg5)")
  public static void __bpf_trace_fib_table_lookup(Ptr<?> __data, @Unsigned int tb_id,
      Ptr<flowi4> flp, Ptr<fib_nh_common> nhc, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_file_check_and_advance_wb_err(Ptr<?> __data, Ptr<file> file,
      @Unsigned @OriginalName("errseq_t") int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_filelock_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_filelock_lock(Ptr<?> __data, Ptr<inode> inode, Ptr<file_lock> fl,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_filemap_set_wb_err(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned @OriginalName("errseq_t") int eseq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_fill_mg_cmtime(Ptr<?> __data, Ptr<inode> inode,
      Ptr<timespec64> ctime, Ptr<timespec64> mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_finish_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_flush_foreign(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned int frn_bdi_id, @Unsigned int frn_memcg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_free_vmap_area_noflush(Ptr<?> __data, @Unsigned long va_start,
      @Unsigned long nr_lazy, @Unsigned long nr_lazy_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_fuse_request_end($arg1, (const struct fuse_req*)$arg2)")
  public static void __bpf_trace_fuse_request_end(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_fuse_request_send($arg1, (const struct fuse_req*)$arg2)")
  public static void __bpf_trace_fuse_request_send(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_generic_add_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_global_dirty_state(Ptr<?> __data, @Unsigned long background_thresh,
      @Unsigned long dirty_thresh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_gpio_direction(Ptr<?> __data, @Unsigned int gpio, int in,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_gpio_value(Ptr<?> __data, @Unsigned int gpio, int get, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_guest_halt_poll_ns(Ptr<?> __data, boolean grow, @Unsigned int _new,
      @Unsigned int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_handshake_alert_class($arg1, (const struct sock*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_handshake_alert_class(Ptr<?> __data, Ptr<sock> sk, char level,
      char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_handshake_complete($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void __bpf_trace_handshake_complete(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_handshake_error_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void __bpf_trace_handshake_error_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_handshake_event_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4)")
  public static void __bpf_trace_handshake_event_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_handshake_fd_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void __bpf_trace_handshake_fd_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hrtimer_class(Ptr<?> __data, Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hrtimer_expire_entry(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      Ptr<java.lang. @OriginalName("ktime_t") Long> now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hrtimer_setup(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      @OriginalName("clockid_t") int clockid, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hrtimer_start(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hugetlbfs__inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hugetlbfs_alloc_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hugetlbfs_fallocate(Ptr<?> __data, Ptr<inode> inode, int mode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hugetlbfs_setattr(Ptr<?> __data, Ptr<inode> inode,
      Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_hwmon_attr_class($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void __bpf_trace_hwmon_attr_class(Ptr<?> __data, int index, String attr_name,
      long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_hwmon_attr_show_string($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void __bpf_trace_hwmon_attr_show_string(Ptr<?> __data, int index, String attr_name,
      String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_hyperv_mmu_flush_tlb_multi($arg1, (const struct cpumask*)$arg2, (const struct flush_tlb_info*)$arg3)")
  public static void __bpf_trace_hyperv_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hyperv_nested_flush_guest_mapping(Ptr<?> __data, @Unsigned long as,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hyperv_nested_flush_guest_mapping_range(Ptr<?> __data,
      @Unsigned long as, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_hyperv_send_ipi_mask($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static void __bpf_trace_hyperv_send_ipi_mask(Ptr<?> __data, Ptr<cpumask> cpus,
      int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_hyperv_send_ipi_one(Ptr<?> __data, int cpu, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_i2c_read($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void __bpf_trace_i2c_read(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_i2c_reply($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void __bpf_trace_i2c_reply(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_i2c_result($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_i2c_result(Ptr<?> __data, Ptr<i2c_adapter> adap, int num,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_i2c_slave($arg1, (const struct i2c_client*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_i2c_slave(Ptr<?> __data, Ptr<i2c_client> client,
      i2c_slave_event event, Ptr<java.lang.Character> val, int cb_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_i2c_write($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void __bpf_trace_i2c_write(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_icc_set_bw(Ptr<?> __data, Ptr<icc_path> p, Ptr<icc_node> n, int i,
      @Unsigned int avg_bw, @Unsigned int peak_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_icc_set_bw_end(Ptr<?> __data, Ptr<icc_path> p, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_icmp_send($arg1, (const struct sk_buff*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_icmp_send(Ptr<?> __data, Ptr<sk_buff> skb, int type, int code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_inet_sk_error_report($arg1, (const struct sock*)$arg2)")
  public static void __bpf_trace_inet_sk_error_report(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_inet_sock_set_state($arg1, (const struct sock*)$arg2, (const int)$arg3, (const int)$arg4)")
  public static void __bpf_trace_inet_sock_set_state(Ptr<?> __data, Ptr<sock> sk, int oldstate,
      int newstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_initcall_finish(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_initcall_level($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_initcall_level(Ptr<?> __data, String level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_initcall_start(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_inode_foreign_history(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned int history) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_inode_switch_wbs(Ptr<?> __data, Ptr<inode> inode,
      Ptr<bdi_writeback> old_wb, Ptr<bdi_writeback> new_wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_complete(Ptr<?> __data, Ptr<io_ring_ctx> ctx, Ptr<?> req,
      Ptr<io_uring_cqe> cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_cqe_overflow(Ptr<?> __data, Ptr<?> ctx,
      @Unsigned long user_data, int res, @Unsigned int cflags, Ptr<?> ocqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_cqring_wait(Ptr<?> __data, Ptr<?> ctx, int min_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_create(Ptr<?> __data, int fd, Ptr<?> ctx,
      @Unsigned int sq_entries, @Unsigned int cq_entries, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_defer(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_fail_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_file_get(Ptr<?> __data, Ptr<io_kiocb> req, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> target_req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_local_work_run(Ptr<?> __data, Ptr<?> ctx, int count,
      @Unsigned int loops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_poll_arm(Ptr<?> __data, Ptr<io_kiocb> req, int mask,
      int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_queue_async_work(Ptr<?> __data, Ptr<io_kiocb> req,
      int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_register(Ptr<?> __data, Ptr<?> ctx, @Unsigned int opcode,
      @Unsigned int nr_files, @Unsigned int nr_bufs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_io_uring_req_failed($arg1, (const struct io_uring_sqe*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_io_uring_req_failed(Ptr<?> __data, Ptr<io_uring_sqe> sqe,
      Ptr<io_kiocb> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_short_write(Ptr<?> __data, Ptr<?> ctx,
      @Unsigned long fpos, @Unsigned long wanted, @Unsigned long got) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_submit_req(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_task_add(Ptr<?> __data, Ptr<io_kiocb> req, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_io_uring_task_work_run(Ptr<?> __data, Ptr<?> tctx,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_iocg_inuse_update($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __bpf_trace_iocg_inuse_update(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iocost_ioc_vrate_adj(Ptr<?> __data, Ptr<ioc> ioc,
      @Unsigned long new_vrate, Ptr<java.lang. @Unsigned Integer> missed_ppm,
      @Unsigned int rq_wait_pct, int nr_lagging, int nr_shortages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_iocost_iocg_forgive_debt($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void __bpf_trace_iocost_iocg_forgive_debt(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned int usage_pct, @Unsigned long old_debt,
      @Unsigned long new_debt, @Unsigned long old_delay, @Unsigned long new_delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_iocost_iocg_state($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __bpf_trace_iocost_iocg_state(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_add_to_ioend(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pos, @Unsigned int dirty_len, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_class(Ptr<?> __data, Ptr<inode> inode, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_dio_complete(Ptr<?> __data, Ptr<kiocb> iocb, int error,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_dio_rw_begin(Ptr<?> __data, Ptr<kiocb> iocb,
      Ptr<iov_iter> iter, @Unsigned int dio_flags, @Unsigned long done_before) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_iomap_iter($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static void __bpf_trace_iomap_iter(Ptr<?> __data, Ptr<iomap_iter> iter, Ptr<?> ops,
      @Unsigned long caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_range_class(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iomap_readpage_class(Ptr<?> __data, Ptr<inode> inode,
      int nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iommu_device_event(Ptr<?> __data, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iommu_error(Ptr<?> __data, Ptr<device> dev, @Unsigned long iova,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_iommu_group_event(Ptr<?> __data, int group_id, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ipi_send_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_ipi_send_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ipi_send_cpumask($arg1, (const struct cpumask*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_ipi_send_cpumask(Ptr<?> __data, Ptr<cpumask> cpumask,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_irq_handler_entry(Ptr<?> __data, int irq, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_irq_handler_exit(Ptr<?> __data, int irq, Ptr<irqaction> action,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_irq_matrix_cpu(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_irq_matrix_global(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_irq_matrix_global_update(Ptr<?> __data, int bit,
      Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_irq_noise($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_irq_noise(Ptr<?> __data, int vector, String desc,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_itimer_expire(Ptr<?> __data, int which, Ptr<pid> pid,
      @Unsigned long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_itimer_state($arg1, $arg2, (const const struct itimerspec64*)$arg3, $arg4)")
  public static void __bpf_trace_itimer_state(Ptr<?> __data, int which, Ptr<itimerspec64> value,
      @Unsigned long expires) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_checkpoint(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_checkpoint_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_chp_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_end_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_handle_extend(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int buffer_credits, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_handle_start_class(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_handle_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int interval, int sync, int requested_blocks,
      int dirtied_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_journal_shrink(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_lock_buffer_stall(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned long stall_ms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_run_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_run_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_shrink_checkpoint_list(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned @OriginalName("tid_t") int last_tid, @Unsigned long nr_freed,
      @Unsigned @OriginalName("tid_t") int next_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_shrink_scan_exit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long nr_shrunk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_submit_inode_data(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_update_log_tail(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned long block_nr,
      @Unsigned long freed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_jbd2_write_superblock(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("blk_opf_t") int write_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_kcompactd_wake_template(Ptr<?> __data, int nid, int order,
      zone_type highest_zoneidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_kfree($arg1, $arg2, (const void*)$arg3)")
  public static void __bpf_trace_kfree(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_kfree_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location,
      skb_drop_reason reason, Ptr<sock> rx_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_kmalloc($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __bpf_trace_kmalloc(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr,
      @Unsigned long bytes_req, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_kmem_cache_alloc($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6)")
  public static void __bpf_trace_kmem_cache_alloc(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s, @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_kmem_cache_free($arg1, $arg2, (const void*)$arg3, (const struct kmem_cache*)$arg4)")
  public static void __bpf_trace_kmem_cache_free(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_advisor(Ptr<?> __data, long scan_time,
      @Unsigned long pages_to_scan, @Unsigned int cpu_percent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_enter_exit_template(Ptr<?> __data, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_merge_one_page(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_merge_with_ksm_page(Ptr<?> __data, Ptr<?> ksm_page,
      @Unsigned long pfn, Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_remove_ksm_page(Ptr<?> __data, @Unsigned long pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_remove_rmap_item(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_ksm_scan_template(Ptr<?> __data, int seq,
      @Unsigned int rmap_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_leases_conflict(Ptr<?> __data, boolean conflict,
      Ptr<file_lease> lease, Ptr<file_lease> breaker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_locks_get_lock_context(Ptr<?> __data, Ptr<inode> inode, int type,
      Ptr<file_lock_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ma_op($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_ma_op(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ma_read($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_ma_read(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_ma_write($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_ma_write(Ptr<?> __data, String fn, Ptr<ma_state> mas,
      @Unsigned long piv, Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_map(Ptr<?> __data, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mark_victim(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_mc_event($arg1, (const unsigned int)$arg2, (const u8*)$arg3, (const u8*)$arg4, (const int)$arg5, (const u8)$arg6, (const s8)$arg7, (const s8)$arg8, (const s8)$arg9, $arg10, (const u8)$arg11, $arg12, (const u8*)$arg13)")
  public static void __bpf_trace_mc_event(Ptr<?> __data, @Unsigned int err_type, String error_msg,
      String label, int error_count, char mc_index, @OriginalName("s8") byte top_layer,
      @OriginalName("s8") byte mid_layer, @OriginalName("s8") byte low_layer,
      @Unsigned long address, char grain_bits, @Unsigned long syndrome, String driver_detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mce_record(Ptr<?> __data, Ptr<mce_hw_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_mctp_key_acquire($arg1, (const struct mctp_sk_key*)$arg2)")
  public static void __bpf_trace_mctp_key_acquire(Ptr<?> __data, Ptr<mctp_sk_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_mctp_key_release($arg1, (const struct mctp_sk_key*)$arg2, $arg3)")
  public static void __bpf_trace_mctp_key_release(Ptr<?> __data, Ptr<mctp_sk_key> key, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mdio_access(Ptr<?> __data, Ptr<mii_bus> bus, char read, char addr,
      @Unsigned int regnum, @Unsigned short val, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_mem_connect($arg1, (const struct xdp_mem_allocator*)$arg2, (const struct xdp_rxq_info*)$arg3)")
  public static void __bpf_trace_mem_connect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa,
      Ptr<xdp_rxq_info> rxq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_mem_disconnect($arg1, (const struct xdp_mem_allocator*)$arg2)")
  public static void __bpf_trace_mem_disconnect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_memcg_flush_stats(Ptr<?> __data, Ptr<mem_cgroup> memcg,
      long stats_updates, boolean force, boolean needs_flush) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_memcg_rstat_events(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      @Unsigned long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_memcg_rstat_stats(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_memory_failure_event(Ptr<?> __data, @Unsigned long pfn, int type,
      int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_migration_pmd(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_migration_pte(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pte, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_calculate_totalreserve_pages(Ptr<?> __data,
      @Unsigned long totalreserve_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_collapse_huge_page(Ptr<?> __data, Ptr<mm_struct> mm,
      int isolated, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_collapse_huge_page_isolate(Ptr<?> __data, Ptr<folio> folio,
      int none_or_zero, int referenced, boolean writable, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_collapse_huge_page_swapin(Ptr<?> __data, Ptr<mm_struct> mm,
      int swapped_in, int referenced, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_begin(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_defer_template(Ptr<?> __data, Ptr<zone> zone,
      int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_end(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_isolate_template(Ptr<?> __data,
      @Unsigned long start_pfn, @Unsigned long end_pfn, @Unsigned long nr_scanned,
      @Unsigned long nr_taken) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_kcompactd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_migratepages(Ptr<?> __data,
      @Unsigned int nr_migratepages, @Unsigned int nr_succeeded) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_suitable_template(Ptr<?> __data, Ptr<zone> zone,
      int order, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_compaction_try_to_compact_pages(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, int prio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_filemap_fault(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned long index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_filemap_op_page_cache(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_filemap_op_page_cache_range(Ptr<?> __data,
      Ptr<address_space> mapping, @Unsigned long index, @Unsigned long last_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_khugepaged_collapse_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> new_folio, @Unsigned long index, @Unsigned long addr, boolean is_shmem,
      Ptr<file> file, int nr, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_khugepaged_scan_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, Ptr<file> file, int present, int swap, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_khugepaged_scan_pmd(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, boolean writable, int referenced, int none_or_zero, int status,
      int unmapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_lru_activate(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_lru_insertion(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_migrate_pages(Ptr<?> __data, @Unsigned long succeeded,
      @Unsigned long failed, @Unsigned long thp_succeeded, @Unsigned long thp_failed,
      @Unsigned long thp_split, @Unsigned long large_folio_split, migrate_mode mode, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_migrate_pages_start(Ptr<?> __data, migrate_mode mode,
      int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page(Ptr<?> __data, Ptr<page> page, @Unsigned int order,
      int migratetype, int percpu_refill) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page_alloc(Ptr<?> __data, Ptr<page> page, @Unsigned int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page_alloc_extfrag(Ptr<?> __data, Ptr<page> page,
      int alloc_order, int fallback_order, int alloc_migratetype, int fallback_migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page_free(Ptr<?> __data, Ptr<page> page, @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page_free_batched(Ptr<?> __data, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_page_pcpu_drain(Ptr<?> __data, Ptr<page> page,
      @Unsigned int order, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_setup_per_zone_lowmem_reserve(Ptr<?> __data, Ptr<zone> zone,
      Ptr<zone> upper_zone, long lowmem_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_setup_per_zone_wmarks(Ptr<?> __data, Ptr<zone> zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_shrink_slab_end(Ptr<?> __data, Ptr<shrinker> shr, int nid,
      int shrinker_retval, long unused_scan_cnt, long new_scan_cnt, long total_scan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_shrink_slab_start(Ptr<?> __data, Ptr<shrinker> shr,
      Ptr<shrink_control> sc, long nr_objects_to_shrink, @Unsigned long cache_items,
      @Unsigned long delta, @Unsigned long total_scan, int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_direct_reclaim_begin_template(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_direct_reclaim_end_template(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_kswapd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_kswapd_wake(Ptr<?> __data, int nid, int zid, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_lru_isolate(Ptr<?> __data, int highest_zoneidx,
      int order, @Unsigned long nr_requested, @Unsigned long nr_scanned, @Unsigned long nr_skipped,
      @Unsigned long nr_taken, int lru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_lru_shrink_active(Ptr<?> __data, int nid,
      @Unsigned long nr_taken, @Unsigned long nr_active, @Unsigned long nr_deactivated,
      @Unsigned long nr_referenced, int priority, int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_lru_shrink_inactive(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat, int priority,
      int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_node_reclaim_begin(Ptr<?> __data, int nid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_reclaim_pages(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_throttled(Ptr<?> __data, int nid, int usec_timeout,
      int usec_delayed, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_wakeup_kswapd(Ptr<?> __data, int nid, int zid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mm_vmscan_write_folio(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mmap_lock(Ptr<?> __data, Ptr<mm_struct> mm, boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mmap_lock_acquire_returned(Ptr<?> __data, Ptr<mm_struct> mm,
      boolean write, boolean success) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mmc_request_done(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mmc_request_start(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_module_free(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_module_load(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_module_refcnt(Ptr<?> __data, Ptr<module> mod, @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_module_request(Ptr<?> __data, String name, boolean wait,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mon_llc_occupancy_limbo(Ptr<?> __data, @Unsigned int ctrl_hw_id,
      @Unsigned int mon_hw_id, int domain_id, @Unsigned long llc_occupancy_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mptcp_dump_mpext(Ptr<?> __data, Ptr<mptcp_ext> mpext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_mptcp_subflow_get_send(Ptr<?> __data,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_msr_trace_class(Ptr<?> __data, @Unsigned int msr,
      @Unsigned long val, int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_napi_poll(Ptr<?> __data, Ptr<napi_struct> napi, int work,
      int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_neigh__update(Ptr<?> __data, Ptr<neighbour> n, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_neigh_create($arg1, $arg2, $arg3, (const void*)$arg4, (const struct neighbour*)$arg5, $arg6)")
  public static void __bpf_trace_neigh_create(Ptr<?> __data, Ptr<neigh_table> tbl,
      Ptr<net_device> dev, Ptr<?> pkey, Ptr<neighbour> n, boolean exempt_from_gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_neigh_update($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6)")
  public static void __bpf_trace_neigh_update(Ptr<?> __data, Ptr<neighbour> n,
      Ptr<java.lang.Character> lladdr, char _new, @Unsigned int flags, @Unsigned int nlmsg_pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_net_dev_rx_exit_template(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_net_dev_rx_verbose_template($arg1, (const struct sk_buff*)$arg2)")
  public static void __bpf_trace_net_dev_rx_verbose_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_net_dev_start_xmit($arg1, (const struct sk_buff*)$arg2, (const struct net_device*)$arg3)")
  public static void __bpf_trace_net_dev_start_xmit(Ptr<?> __data, Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_net_dev_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_net_dev_xmit(Ptr<?> __data, Ptr<sk_buff> skb, int rc,
      Ptr<net_device> dev, @Unsigned int skb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_net_dev_xmit_timeout(Ptr<?> __data, Ptr<net_device> dev,
      int queue_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_netlink_extack($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_netlink_extack(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_nmi_handler(Ptr<?> __data, Ptr<?> handler, long delta_ns,
      int handled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_nmi_noise(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_non_standard_event($arg1, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg2, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg3, (const u8*)$arg4, (const u8)$arg5, (const u8*)$arg6, (const unsigned int)$arg7)")
  public static void __bpf_trace_non_standard_event(Ptr<?> __data,
      Ptr<@OriginalName("guid_t") uuid_t> sec_type, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev, Ptr<java.lang.Character> err, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_notifier_info(Ptr<?> __data, Ptr<?> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_oom_score_adj_update(Ptr<?> __data, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_osnoise_sample(Ptr<?> __data, Ptr<osnoise_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_page_pool_release($arg1, (const struct page_pool*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_page_pool_release(Ptr<?> __data, Ptr<page_pool> pool, int inflight,
      @Unsigned int hold, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_page_pool_state_hold($arg1, (const struct page_pool*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_page_pool_state_hold(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int hold) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_page_pool_state_release($arg1, (const struct page_pool*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_page_pool_state_release(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_page_pool_update_nid($arg1, (const struct page_pool*)$arg2, $arg3)")
  public static void __bpf_trace_page_pool_update_nid(Ptr<?> __data, Ptr<page_pool> pool,
      int new_nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_cfs_tp(Ptr<?> __data, Ptr<cfs_rq> cfs_rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_dl_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_hw_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_irq_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_rt_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pelt_se_tp(Ptr<?> __data, Ptr<sched_entity> se) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_percpu_alloc_percpu(Ptr<?> __data, @Unsigned long call_site,
      boolean reserved, boolean is_atomic, @Unsigned long size, @Unsigned long align,
      Ptr<?> base_addr, int off, Ptr<?> ptr, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_percpu_alloc_percpu_fail(Ptr<?> __data, boolean reserved,
      boolean is_atomic, @Unsigned long size, @Unsigned long align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_percpu_create_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_percpu_destroy_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_percpu_free_percpu(Ptr<?> __data, Ptr<?> base_addr, int off,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pm_qos_update(Ptr<?> __data, pm_qos_req_action action,
      int prev_value, int curr_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_prq_report(Ptr<?> __data, Ptr<intel_iommu> iommu, Ptr<device> dev,
      @Unsigned long dw0, @Unsigned long dw1, @Unsigned long dw2, @Unsigned long dw3,
      @Unsigned long seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pseudo_lock_l2(Ptr<?> __data, @Unsigned long l2_hits,
      @Unsigned long l2_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pseudo_lock_l3(Ptr<?> __data, @Unsigned long l3_hits,
      @Unsigned long l3_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pseudo_lock_mem_latency(Ptr<?> __data, @Unsigned int latency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pstate_sample(Ptr<?> __data, @Unsigned int core_busy,
      @Unsigned int scaled_busy, @Unsigned int from, @Unsigned int to, @Unsigned long mperf,
      @Unsigned long aperf, @Unsigned long tsc, @Unsigned int freq, @Unsigned int io_boost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_purge_vmap_area_lazy(Ptr<?> __data, @Unsigned long start,
      @Unsigned long end, @Unsigned int npurged) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_pwm($arg1, $arg2, (const struct pwm_state*)$arg3, $arg4)")
  public static void __bpf_trace_pwm(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<pwm_state> state,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_pwm_read_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_pwm_round_waveform_fromhw($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_pwm_round_waveform_fromhw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<?> wfhw, Ptr<pwm_waveform> wf, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_pwm_round_waveform_tohw($arg1, $arg2, (const struct pwm_waveform*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_pwm_round_waveform_tohw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<pwm_waveform> wf, Ptr<?> wfhw, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_pwm_write_waveform($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static void __bpf_trace_pwm_write_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_qdisc_create($arg1, (const struct Qdisc_ops*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_qdisc_create(Ptr<?> __data, Ptr<Qdisc_ops> ops,
      Ptr<net_device> dev, @Unsigned int parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_qdisc_dequeue($arg1, $arg2, (const struct netdev_queue*)$arg3, $arg4, $arg5)")
  public static void __bpf_trace_qdisc_dequeue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, int packets, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_qdisc_destroy(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_qdisc_enqueue($arg1, $arg2, (const struct netdev_queue*)$arg3, $arg4)")
  public static void __bpf_trace_qdisc_enqueue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_qdisc_reset(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_qi_submit(Ptr<?> __data, Ptr<intel_iommu> iommu,
      @Unsigned long qw0, @Unsigned long qw1, @Unsigned long qw2, @Unsigned long qw3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_rcu_stall_warning($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static void __bpf_trace_rcu_stall_warning(Ptr<?> __data, String rcuname, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_rcu_utilization($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_rcu_utilization(Ptr<?> __data, String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_reclaim_retry_zone(Ptr<?> __data, Ptr<zoneref> zoneref, int order,
      @Unsigned long reclaimable, @Unsigned long available, @Unsigned long min_wmark,
      int no_progress_loops, boolean wmark_check) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_regcache_drop_region(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_regcache_sync($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void __bpf_trace_regcache_sync(Ptr<?> __data, Ptr<regmap> map, String type,
      String status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_regmap_async(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_regmap_block(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_regmap_bool(Ptr<?> __data, Ptr<regmap> map, boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_regmap_bulk($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static void __bpf_trace_regmap_bulk(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_regmap_reg(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_regulator_basic($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_regulator_basic(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_regulator_range($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_regulator_range(Ptr<?> __data, String name, int min, int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_regulator_value($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_regulator_value(Ptr<?> __data, String name, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rpm_internal(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rpm_return_int(Ptr<?> __data, Ptr<device> dev, @Unsigned long ip,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rpm_status(Ptr<?> __data, Ptr<device> dev, rpm_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rseq_ip_fixup(Ptr<?> __data, @Unsigned long regs_ip,
      @Unsigned long start_ip, @Unsigned long post_commit_offset, @Unsigned long abort_ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rseq_update(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rss_stat(Ptr<?> __data, Ptr<mm_struct> mm, int member) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_alarm_irq_enable(Ptr<?> __data, @Unsigned int enabled,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_irq_set_freq(Ptr<?> __data, int freq, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_irq_set_state(Ptr<?> __data, int enabled, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_offset_class(Ptr<?> __data, long offset, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_time_alarm_class(Ptr<?> __data,
      @OriginalName("time64_t") long secs, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rtc_timer_class(Ptr<?> __data, Ptr<rtc_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_rv_retries_error(Ptr<?> __data, String name, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sample_threshold(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration, @Unsigned long interference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_compute_energy_tp(Ptr<?> __data, Ptr<task_struct> p,
      int dst_cpu, @Unsigned long energy, @Unsigned long max_util, @Unsigned long busy_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_cpu_capacity_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_entry_tp(Ptr<?> __data, boolean preempt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_exit_tp(Ptr<?> __data, boolean is_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_sched_ext_dump($arg1, (const u8*)$arg2)")
  public static void __bpf_trace_sched_ext_dump(Ptr<?> __data, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_sched_ext_event($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_sched_ext_event(Ptr<?> __data, String name, long delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_kthread_stop(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_kthread_stop_ret(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_kthread_work_execute_end(Ptr<?> __data,
      Ptr<kthread_work> work, @OriginalName("kthread_work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_kthread_work_execute_start(Ptr<?> __data,
      Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_kthread_work_queue_work(Ptr<?> __data,
      Ptr<kthread_worker> worker, Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_migrate_task(Ptr<?> __data, Ptr<task_struct> p,
      int dest_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_move_numa(Ptr<?> __data, Ptr<task_struct> tsk, int src_cpu,
      int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_numa_pair_template(Ptr<?> __data, Ptr<task_struct> src_tsk,
      int src_cpu, Ptr<task_struct> dst_tsk, int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_overutilized_tp(Ptr<?> __data, Ptr<root_domain> rd,
      boolean overutilized) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_pi_setprio(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<task_struct> pi_task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_prepare_exec(Ptr<?> __data, Ptr<task_struct> task,
      Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_exec(Ptr<?> __data, Ptr<task_struct> p,
      @OriginalName("pid_t") int old_pid, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_exit(Ptr<?> __data, Ptr<task_struct> p,
      boolean group_dead) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_fork(Ptr<?> __data, Ptr<task_struct> parent,
      Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_hang(Ptr<?> __data, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_process_wait(Ptr<?> __data, Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_set_need_resched_tp(Ptr<?> __data, Ptr<task_struct> tsk,
      int cpu, int tif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_skip_cpuset_numa(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<nodemask_t> mem_allowed_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_skip_vma_numa(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<vm_area_struct> vma, numa_vmaskip_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_stat_runtime(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long runtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_stat_template(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_switch(Ptr<?> __data, boolean preempt, Ptr<task_struct> prev,
      Ptr<task_struct> next, @Unsigned int prev_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_update_nr_running_tp(Ptr<?> __data, Ptr<rq> rq, int change) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_util_est_cfs_tp(Ptr<?> __data, Ptr<cfs_rq> cfs_rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_util_est_se_tp(Ptr<?> __data, Ptr<sched_entity> se) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_wake_idle_without_ipi(Ptr<?> __data, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sched_wakeup_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_cmd_done_timeout_template(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_dispatch_cmd_error(Ptr<?> __data, Ptr<scsi_cmnd> cmd,
      int rtn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_dispatch_cmd_start(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_eh_wakeup(Ptr<?> __data, Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_prepare_zone_append(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long lba, @Unsigned int wp_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_scsi_zone_wp_update(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long rq_sector, @Unsigned int wp_offset,
      @Unsigned int good_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_selinux_audited($arg1, $arg2, $arg3, $arg4, (const u8*)$arg5)")
  public static void __bpf_trace_selinux_audited(Ptr<?> __data, Ptr<selinux_audit_data> sad,
      String scontext, String tcontext, String tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_signal_deliver(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<k_sigaction> ka) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_signal_generate(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<task_struct> task, int group, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_sk_data_ready($arg1, (const struct sock*)$arg2)")
  public static void __bpf_trace_sk_data_ready(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_skb_copy_datagram_iovec($arg1, (const struct sk_buff*)$arg2, $arg3)")
  public static void __bpf_trace_skb_copy_datagram_iovec(Ptr<?> __data, Ptr<sk_buff> skb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_skip_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_smbus_read($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __bpf_trace_smbus_read(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_smbus_reply($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data*)$arg8, $arg9)")
  public static void __bpf_trace_smbus_reply(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_smbus_result($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __bpf_trace_smbus_result(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_smbus_write($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data*)$arg8)")
  public static void __bpf_trace_smbus_write(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sock_exceed_buf_limit(Ptr<?> __data, Ptr<sock> sk, Ptr<proto> prot,
      long allocated, int kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sock_msg_length(Ptr<?> __data, Ptr<sock> sk, int ret, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sock_rcvqueue_full(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_softirq(Ptr<?> __data, @Unsigned int vec_nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_softirq_noise(Ptr<?> __data, int vector, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_controller(Ptr<?> __data, Ptr<spi_controller> controller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_message(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_message_done(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_set_cs(Ptr<?> __data, Ptr<spi_device> spi, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_setup(Ptr<?> __data, Ptr<spi_device> spi, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_spi_transfer(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_start_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_subflow_check_data_avail(Ptr<?> __data, char status,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_suspend_resume($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void __bpf_trace_suspend_resume(Ptr<?> __data, String action, int val,
      boolean start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_swiotlb_bounced(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dev_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sync_timeline(Ptr<?> __data, Ptr<sync_timeline> timeline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sys_enter(Ptr<?> __data, Ptr<pt_regs> regs, long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_sys_exit(Ptr<?> __data, Ptr<pt_regs> regs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_task_newtask(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_task_prctl_unknown(Ptr<?> __data, int option, @Unsigned long arg2,
      @Unsigned long arg3, @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_task_rename($arg1, $arg2, (const u8*)$arg3)")
  public static void __bpf_trace_task_rename(Ptr<?> __data, Ptr<task_struct> task, String comm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tasklet(Ptr<?> __data, Ptr<tasklet_struct> t, Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_ao_event($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __bpf_trace_tcp_ao_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_ao_event_sk($arg1, (const struct sock*)$arg2, (const u8)$arg3, (const u8)$arg4)")
  public static void __bpf_trace_tcp_ao_event_sk(Ptr<?> __data, Ptr<sock> sk, char keyid,
      char rnext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_ao_event_sne($arg1, (const struct sock*)$arg2, $arg3)")
  public static void __bpf_trace_tcp_ao_event_sne(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_cong_state_set($arg1, $arg2, (const u8)$arg3)")
  public static void __bpf_trace_tcp_cong_state_set(Ptr<?> __data, Ptr<sock> sk, char ca_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_cwnd_reduction_tp($arg1, (const struct sock*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_tcp_cwnd_reduction_tp(Ptr<?> __data, Ptr<sock> sk,
      int newly_acked_sacked, int newly_lost, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tcp_event_sk(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_event_skb($arg1, (const struct sk_buff*)$arg2)")
  public static void __bpf_trace_tcp_event_skb(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_hash_event($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3)")
  public static void __bpf_trace_tcp_hash_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_probe($arg1, $arg2, (const struct sk_buff*)$arg3)")
  public static void __bpf_trace_tcp_probe(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tcp_rcvbuf_grow(Ptr<?> __data, Ptr<sock> sk, int time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_retransmit_skb($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, $arg4)")
  public static void __bpf_trace_tcp_retransmit_skb(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_retransmit_synack($arg1, (const struct sock*)$arg2, (const struct request_sock*)$arg3)")
  public static void __bpf_trace_tcp_retransmit_synack(Ptr<?> __data, Ptr<sock> sk,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_send_reset($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, (const enum sk_rst_reason)$arg4)")
  public static void __bpf_trace_tcp_send_reset(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb__nullable, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tcp_sendmsg_locked($arg1, (const struct sock*)$arg2, (const struct msghdr*)$arg3, (const struct sk_buff*)$arg4, $arg5)")
  public static void __bpf_trace_tcp_sendmsg_locked(Ptr<?> __data, Ptr<sock> sk, Ptr<msghdr> msg,
      Ptr<sk_buff> skb, int size_goal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_test_pages_isolated(Ptr<?> __data, @Unsigned long start_pfn,
      @Unsigned long end_pfn, @Unsigned long fin_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_power_actor(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int actor_id, @Unsigned int req_power, @Unsigned int granted_power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_power_allocator(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      @Unsigned int total_req_power, @Unsigned int total_granted_power, int num_actors,
      @Unsigned int power_range, @Unsigned int max_allocatable_power, int current_temp,
      int delta_temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_power_allocator_pid(Ptr<?> __data,
      Ptr<thermal_zone_device> tz, int err, int err_integral, long p, long i, long d, int output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_power_devfreq_get_power(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, Ptr<devfreq_dev_status> status, @Unsigned long freq,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_power_devfreq_limit(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long freq, @Unsigned long cdev_state,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_temperature(Ptr<?> __data, Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thermal_zone_trip(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int trip, thermal_trip_type trip_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_thread_noise(Ptr<?> __data, Ptr<task_struct> t,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tick_stop(Ptr<?> __data, int success, int dependency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_timer_base_idle(Ptr<?> __data, boolean is_idle,
      @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_timer_class(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_timer_expire_entry(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long baseclk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_timer_start(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long bucket_expiry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_timerlat_sample(Ptr<?> __data, Ptr<timerlat_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tlb_flush(Ptr<?> __data, int reason, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tls_contenttype($arg1, (const struct sock*)$arg2, $arg3)")
  public static void __bpf_trace_tls_contenttype(Ptr<?> __data, Ptr<sock> sk, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_connect_child_parent(Ptr<?> __data, Ptr<tmigr_group> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_connect_cpu_parent(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_cpugroup(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_group_and_cpu(Ptr<?> __data, Ptr<tmigr_group> group,
      tmigr_state state, @Unsigned int childmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_group_set(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_handle_remote(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_idle(Ptr<?> __data, Ptr<tmigr_cpu> tmc,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_tmigr_update_events(Ptr<?> __data, Ptr<tmigr_group> child,
      Ptr<tmigr_group> group, tmigr_state childstate, tmigr_state groupstate,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_track_foreign_dirty(Ptr<?> __data, Ptr<folio> folio,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tsm_mr_read($arg1, (const struct tsm_measurement_register*)$arg2)")
  public static void __bpf_trace_tsm_mr_read(Ptr<?> __data, Ptr<tsm_measurement_register> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tsm_mr_refresh($arg1, (const struct tsm_measurement_register*)$arg2, $arg3)")
  public static void __bpf_trace_tsm_mr_refresh(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_tsm_mr_write($arg1, (const struct tsm_measurement_register*)$arg2, (const u8*)$arg3)")
  public static void __bpf_trace_tsm_mr_write(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_udp_fail_queue_rcv_skb(Ptr<?> __data, int rc, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_unmap(Ptr<?> __data, @Unsigned long iova, @Unsigned long size,
      @Unsigned long unmapped_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_activate(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean can_reserve, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_alloc(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, boolean reserved, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_alloc_managed(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_config(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, @Unsigned int cpu, @Unsigned int apicdest) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_free_moved(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int cpu, @Unsigned int vector, boolean is_managed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_mod(Ptr<?> __data, @Unsigned int irq, @Unsigned int vector,
      @Unsigned int cpu, @Unsigned int prev_vector, @Unsigned int prev_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_reserve(Ptr<?> __data, @Unsigned int irq, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_setup(Ptr<?> __data, @Unsigned int irq, boolean is_legacy,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vector_teardown(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean has_reserved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_vm_unmapped_area(Ptr<?> __data, @Unsigned long addr,
      Ptr<vm_unmapped_area_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_wake_reaper(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_wakeup_source($arg1, (const u8*)$arg2, $arg3)")
  public static void __bpf_trace_wakeup_source(Ptr<?> __data, String name, @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_watchdog_set_timeout(Ptr<?> __data, Ptr<watchdog_device> wdd,
      @Unsigned int timeout, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_watchdog_template(Ptr<?> __data, Ptr<watchdog_device> wdd,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_wbc_class(Ptr<?> __data, Ptr<writeback_control> wbc,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_wbt_lat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned long lat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_wbt_stat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_wbt_step($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __bpf_trace_wbt_step(Ptr<?> __data, Ptr<backing_dev_info> bdi, String msg,
      int step, @Unsigned long window, @Unsigned int bg, @Unsigned int normal, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_wbt_timer(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned int status, int step, @Unsigned int inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_workqueue_activate_work(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_workqueue_execute_end(Ptr<?> __data, Ptr<work_struct> work,
      @OriginalName("work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_workqueue_execute_start(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_workqueue_queue_work(Ptr<?> __data, int req_cpu,
      Ptr<pool_workqueue> pwq, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_bdi_register(Ptr<?> __data, Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_class(Ptr<?> __data, Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_dirty_inode_template(Ptr<?> __data, Ptr<inode> inode,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_folio_template(Ptr<?> __data, Ptr<folio> folio,
      Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_inode_template(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_pages_written(Ptr<?> __data, long pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_queue_io(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work, @Unsigned long dirtied_before, int moved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_sb_inodes_requeue(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_single_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_work_class(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_writeback_write_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_x86_fpu(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_x86_irq_vector(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xdp_bulk_tx($arg1, (const struct net_device*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_xdp_bulk_tx(Ptr<?> __data, Ptr<net_device> dev, int sent,
      int drops, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xdp_cpumap_enqueue(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int to_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xdp_cpumap_kthread(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int sched, Ptr<xdp_cpumap_stats> xdp_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xdp_devmap_xmit($arg1, (const struct net_device*)$arg2, (const struct net_device*)$arg3, $arg4, $arg5, $arg6)")
  public static void __bpf_trace_xdp_devmap_xmit(Ptr<?> __data, Ptr<net_device> from_dev,
      Ptr<net_device> to_dev, int sent, int drops, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xdp_exception($arg1, (const struct net_device*)$arg2, (const struct bpf_prog*)$arg3, $arg4)")
  public static void __bpf_trace_xdp_exception(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<bpf_prog> xdp, @Unsigned int act) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xdp_redirect_template($arg1, (const struct net_device*)$arg2, (const struct bpf_prog*)$arg3, (const void*)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __bpf_trace_xdp_redirect_template(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<bpf_prog> xdp, Ptr<?> tgt, int err, bpf_map_type map_type, @Unsigned int map_id,
      @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xen_cpu_load_idt($arg1, (const struct desc_ptr*)$arg2)")
  public static void __bpf_trace_xen_cpu_load_idt(Ptr<?> __data, Ptr<desc_ptr> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xen_cpu_set_ldt($arg1, (const void*)$arg2, $arg3)")
  public static void __bpf_trace_xen_cpu_set_ldt(Ptr<?> __data, Ptr<?> addr,
      @Unsigned int entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xen_cpu_write_gdt_entry($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static void __bpf_trace_xen_cpu_write_gdt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, Ptr<?> desc, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xen_cpu_write_idt_entry($arg1, $arg2, $arg3, (const gate_struct*)$arg4)")
  public static void __bpf_trace_xen_cpu_write_idt_entry(Ptr<?> __data,
      Ptr<@OriginalName("gate_desc") gate_struct> dt, int entrynum,
      Ptr<@OriginalName("gate_desc") gate_struct> ent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_cpu_write_ldt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, @Unsigned long desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc__batch(Ptr<?> __data, xen_lazy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_callback(Ptr<?> __data,
      @OriginalName("xen_mc_callback_fn_t") Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_entry(Ptr<?> __data, Ptr<multicall_entry> mc,
      @Unsigned int nargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_entry_alloc(Ptr<?> __data, @Unsigned long args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_extend_args(Ptr<?> __data, @Unsigned long op,
      @Unsigned long args, xen_mc_extend_args res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_flush(Ptr<?> __data, @Unsigned int mcidx,
      @Unsigned int argidx, @Unsigned int cbidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mc_flush_reason(Ptr<?> __data, xen_mc_flush_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu__set_pte(Ptr<?> __data, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_alloc_ptpage(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long pfn, @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__bpf_trace_xen_mmu_flush_tlb_multi($arg1, (const struct cpumask*)$arg2, $arg3, $arg4, $arg5)")
  public static void __bpf_trace_xen_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<mm_struct> mm, @Unsigned long addr, @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_flush_tlb_one_user(Ptr<?> __data, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_pgd(Ptr<?> __data, Ptr<mm_struct> mm, Ptr<pgd_t> pgd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_ptep_modify_prot(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long addr, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_release_ptpage(Ptr<?> __data, @Unsigned long pfn,
      @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_set_p4d(Ptr<?> __data, Ptr<p4d_t> p4dp,
      Ptr<p4d_t> user_p4dp, p4d_t p4dval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_set_pmd(Ptr<?> __data, Ptr<pmd_t> pmdp, pmd_t pmdval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_set_pud(Ptr<?> __data, Ptr<pud_t> pudp, pud_t pudval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xen_mmu_write_cr3(Ptr<?> __data, boolean kernel,
      @Unsigned long cr3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_dbc_log_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_ctrl_ctx(Ptr<?> __data,
      Ptr<xhci_input_control_ctx> ctrl_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_ctx(Ptr<?> __data, Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx, @Unsigned int ep_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_doorbell(Ptr<?> __data, @Unsigned int slot,
      @Unsigned int doorbell) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_ep_ctx(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_free_virt_dev(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_msg(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_portsc(Ptr<?> __data, Ptr<xhci_port> port,
      @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_ring(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_slot_ctx(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_stream_ctx(Ptr<?> __data, Ptr<xhci_stream_info> info,
      @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_trb(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_urb(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trace_xhci_log_virt_dev(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_enter(Ptr<bpf_tramp_image> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_exit(Ptr<bpf_tramp_image> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_image_put_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_image_put_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_image_put_rcu_tasks(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_tramp_image_release(Ptr<percpu_ref> pcref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_trampoline_link_prog(Ptr<bpf_tramp_link> link, Ptr<bpf_trampoline> tr,
      Ptr<bpf_prog> tgt_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __bpf_trap() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_xdp_load_bytes(Ptr<xdp_buff> xdp, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __bpf_xdp_store_bytes(Ptr<xdp_buff> xdp, @Unsigned int offset, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_adj_branches($arg1, $arg2, $arg3, $arg4, (const _Bool)$arg5)")
  public static int bpf_adj_branches(Ptr<bpf_prog> prog, @Unsigned int pos, int end_old,
      int end_new, boolean probe_pass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_adj_linfo_after_remove(Ptr<bpf_verifier_env> env, @Unsigned int off,
      @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_arch_poke_desc_update(Ptr<bpf_jit_poke_descriptor> poke,
      Ptr<bpf_prog> _new, Ptr<bpf_prog> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_arch_text_copy(Ptr<?> dst, Ptr<?> src, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_arch_text_invalidate(Ptr<?> dst, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_arch_text_poke(Ptr<?> ip, bpf_text_poke_type t, Ptr<?> old_addr,
      Ptr<?> new_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_arch_uaddress_limit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("")
  public static Ptr<?> bpf_arena_alloc_pages(Ptr<?> p__map, Ptr<?> addr__ign,
      @Unsigned int page_cnt, int node_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("")
  public static void bpf_arena_free_pages(Ptr<?> p__map, Ptr<?> ptr__ign, @Unsigned int page_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_arena_get_kern_vm_start(Ptr<bpf_arena> arena) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_arena_get_user_vm_start(Ptr<bpf_arena> arena) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("")
  public static int bpf_arena_reserve_pages(Ptr<?> p__map, Ptr<?> ptr__ign,
      @Unsigned int page_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_array_map_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_array_map_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_array_map_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_array_map_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_audit_prog((const struct bpf_prog*)$arg1, $arg2)")
  public static void bpf_audit_prog(Ptr<bpf_prog> prog, @Unsigned int op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_base_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_base_func_proto(bpf_func_id func_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_bind(@Unsigned long ctx, @Unsigned long addr,
      @Unsigned long addr_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_bprintf_cleanup(Ptr<bpf_bprintf_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_bprintf_prepare((const u8*)$arg1, $arg2, (const long long unsigned int*)$arg3, $arg4, $arg5)")
  public static int bpf_bprintf_prepare(String fmt, @Unsigned int fmt_size,
      Ptr<java.lang. @Unsigned Long> raw_args, @Unsigned int num_args, Ptr<bpf_bprintf_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_bprm_opts_set(@Unsigned long bprm, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_btf_find_by_name_kind(@Unsigned long name,
      @Unsigned long name_sz, @Unsigned long kind, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_btf_show_fdinfo(Ptr<seq_file> m, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_build_state($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static int bpf_build_state(Ptr<net> net, Ptr<nlattr> nla, @Unsigned int family, Ptr<?> cfg,
      Ptr<Ptr<lwtunnel_state>> ts, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_cast_to_kern_ctx(Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> bpf_cgroup_acquire(Ptr<cgroup> cgrp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> bpf_cgroup_ancestor(Ptr<cgroup> cgrp, int level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static cgroup_bpf_attach_type bpf_cgroup_atype_find(bpf_attach_type attach_type,
      @Unsigned int attach_btf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_atype_get(@Unsigned int attach_btf_id, int cgroup_atype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_atype_put(int cgroup_atype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> bpf_cgroup_from_id(@Unsigned long cgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_cgroup_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_cgroup_link_detach(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cgroup_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_cgroup_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cgroup_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_cgroup_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cgroup_read_xattr($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_cgroup_read_xattr(Ptr<cgroup> cgroup, String name__str,
      Ptr<bpf_dynptr> value_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_release(Ptr<cgroup> cgrp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_release_dtor(Ptr<?> cgrp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_cgroup_storage> bpf_cgroup_storage_alloc(Ptr<bpf_prog> prog,
      bpf_cgroup_storage_type stype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_cgroup_storage_assign(Ptr<bpf_prog_aux> aux, Ptr<bpf_map> _map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_storage_free(Ptr<bpf_cgroup_storage> storage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_storage_link(Ptr<bpf_cgroup_storage> storage, Ptr<cgroup> cgroup,
      bpf_attach_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_storage_unlink(Ptr<bpf_cgroup_storage> storage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgroup_storages_free(Ptr<Ptr<bpf_cgroup_storage>> storages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_cgrp_storage_delete(@Unsigned long map, @Unsigned long cgroup,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_cgrp_storage_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cgrp_storage_free(Ptr<cgroup> cgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_cgrp_storage_get(@Unsigned long map, @Unsigned long cgroup,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_cgrp_storage_lookup_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_cgrp_storage_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_check(Ptr<Ptr<bpf_prog>> prog, Ptr<bpf_attr> attr,
      @OriginalName("bpfptr_t") sockptr_t uattr, @Unsigned int uattr_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_check_attach_target($arg1, (const struct bpf_prog*)$arg2, (const struct bpf_prog*)$arg3, $arg4, $arg5)")
  public static int bpf_check_attach_target(Ptr<bpf_verifier_log> log, Ptr<bpf_prog> prog,
      Ptr<bpf_prog> tgt_prog, @Unsigned int btf_id, Ptr<bpf_attach_target_info> tgt_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_check_classic((const struct sock_filter*)$arg1, $arg2)")
  public static int bpf_check_classic(Ptr<sock_filter> filter, @Unsigned int flen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_check_timed_may_goto(Ptr<bpf_timed_may_goto> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_check_uarg_tail_zero(@OriginalName("bpfptr_t") sockptr_t uaddr,
      @Unsigned long expected_size, @Unsigned long actual_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_clone_redirect(@Unsigned long skb, @Unsigned long ifindex,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_lru_node> bpf_common_lru_pop_free(Ptr<bpf_lru> lru, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_common_lru_populate(Ptr<bpf_lru> lru, Ptr<?> buf,
      @Unsigned int node_offset, @Unsigned int elem_size, @Unsigned int nr_elems) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_convert_ctx_access($arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int bpf_convert_ctx_access(bpf_access_type type, Ptr<bpf_insn> si,
      Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog, Ptr<java.lang. @Unsigned Integer> target_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_convert_filter(Ptr<sock_filter> prog, int len, Ptr<bpf_prog> new_prog,
      Ptr<java.lang.Integer> new_len, Ptr<java.lang. @OriginalName("bool") Boolean> seen_ld_abs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_copy_from_user(@Unsigned long dst, @Unsigned long size,
      @Unsigned long user_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_copy_from_user_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_str($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static int bpf_copy_from_user_str(Ptr<?> dst, @Unsigned int dst__sz,
      Ptr<?> unsafe_ptr__ign, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_str_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_copy_from_user_str_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_copy_from_user_task(@Unsigned long dst, @Unsigned long size,
      @Unsigned long user_ptr, @Unsigned long tsk, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_task_dynptr($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static int bpf_copy_from_user_task_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_task_str($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static int bpf_copy_from_user_task_str(Ptr<?> dst, @Unsigned int dst__sz,
      Ptr<?> unsafe_ptr__ign, Ptr<task_struct> tsk, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_from_user_task_str_dynptr($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static int bpf_copy_from_user_task_str_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_copy_to_user($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static int bpf_copy_to_user(String ubuf, String buf, @Unsigned int ulen,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_add_cands($arg1, (const struct btf*)$arg2, $arg3)")
  public static Ptr<bpf_cand_cache> bpf_core_add_cands(Ptr<bpf_cand_cache> cands, Ptr<btf> targ_btf,
      int targ_start_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_apply($arg1, (const struct bpf_core_relo*)$arg2, $arg3, $arg4)")
  public static int bpf_core_apply(Ptr<bpf_core_ctx> ctx, Ptr<bpf_core_relo> relo, int relo_idx,
      Ptr<?> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_calc_field_relo((const u8*)$arg1, (const struct bpf_core_relo*)$arg2, (const struct bpf_core_spec*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int bpf_core_calc_field_relo(String prog_name, Ptr<bpf_core_relo> relo,
      Ptr<bpf_core_spec> spec, Ptr<java.lang. @Unsigned Long> val,
      Ptr<java.lang. @Unsigned Integer> field_sz, Ptr<java.lang. @Unsigned Integer> type_id,
      Ptr<java.lang. @OriginalName("bool") Boolean> validate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_calc_relo((const u8*)$arg1, (const struct bpf_core_relo*)$arg2, $arg3, (const struct bpf_core_spec*)$arg4, (const struct bpf_core_spec*)$arg5, $arg6)")
  public static int bpf_core_calc_relo(String prog_name, Ptr<bpf_core_relo> relo, int relo_idx,
      Ptr<bpf_core_spec> local_spec, Ptr<bpf_core_spec> targ_spec, Ptr<bpf_core_relo_res> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_calc_relo_insn((const u8*)$arg1, (const struct bpf_core_relo*)$arg2, $arg3, (const struct btf*)$arg4, $arg5, $arg6, $arg7)")
  public static int bpf_core_calc_relo_insn(String prog_name, Ptr<bpf_core_relo> relo, int relo_idx,
      Ptr<btf> local_btf, Ptr<bpf_core_cand_list> cands, Ptr<bpf_core_spec> specs_scratch,
      Ptr<bpf_core_relo_res> targ_res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_calc_type_relo((const struct bpf_core_relo*)$arg1, (const struct bpf_core_spec*)$arg2, $arg3, $arg4)")
  public static int bpf_core_calc_type_relo(Ptr<bpf_core_relo> relo, Ptr<bpf_core_spec> spec,
      Ptr<java.lang. @Unsigned Long> val, Ptr<java.lang. @OriginalName("bool") Boolean> validate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_essential_name_len((const u8*)$arg1)")
  public static @Unsigned long bpf_core_essential_name_len(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_fields_are_compat((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4)")
  public static int bpf_core_fields_are_compat(Ptr<btf> local_btf, @Unsigned int local_id,
      Ptr<btf> targ_btf, @Unsigned int targ_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_format_spec($arg1, $arg2, (const struct bpf_core_spec*)$arg3)")
  public static int bpf_core_format_spec(String buf, @Unsigned long buf_sz,
      Ptr<bpf_core_spec> spec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_match_member((const struct btf*)$arg1, (const struct bpf_core_accessor*)$arg2, (const struct btf*)$arg3, $arg4, $arg5, $arg6)")
  public static int bpf_core_match_member(Ptr<btf> local_btf, Ptr<bpf_core_accessor> local_acc,
      Ptr<btf> targ_btf, @Unsigned int targ_id, Ptr<bpf_core_spec> spec,
      Ptr<java.lang. @Unsigned Integer> next_targ_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_names_match((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4)")
  public static boolean bpf_core_names_match(Ptr<btf> local_btf, @Unsigned long local_name_off,
      Ptr<btf> targ_btf, @Unsigned long targ_name_off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_parse_spec((const u8*)$arg1, (const struct btf*)$arg2, (const struct bpf_core_relo*)$arg3, $arg4)")
  public static int bpf_core_parse_spec(String prog_name, Ptr<btf> btf, Ptr<bpf_core_relo> relo,
      Ptr<bpf_core_spec> spec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_patch_insn((const u8*)$arg1, $arg2, $arg3, (const struct bpf_core_relo*)$arg4, $arg5, (const struct bpf_core_relo_res*)$arg6)")
  public static int bpf_core_patch_insn(String prog_name, Ptr<bpf_insn> insn, int insn_idx,
      Ptr<bpf_core_relo> relo, int relo_idx, Ptr<bpf_core_relo_res> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_spec_match($arg1, (const struct btf*)$arg2, $arg3, $arg4)")
  public static int bpf_core_spec_match(Ptr<bpf_core_spec> local_spec, Ptr<btf> targ_btf,
      @Unsigned int targ_id, Ptr<bpf_core_spec> targ_spec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_types_are_compat((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4)")
  public static int bpf_core_types_are_compat(Ptr<btf> local_btf, @Unsigned int local_id,
      Ptr<btf> targ_btf, @Unsigned int targ_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_core_types_match((const struct btf*)$arg1, $arg2, (const struct btf*)$arg3, $arg4)")
  public static int bpf_core_types_match(Ptr<btf> local_btf, @Unsigned int local_id,
      Ptr<btf> targ_btf, @Unsigned int targ_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_cpumask> bpf_cpumask_acquire(Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_and($arg1, (const struct cpumask*)$arg2, (const struct cpumask*)$arg3)")
  public static boolean bpf_cpumask_and(Ptr<bpf_cpumask> dst, Ptr<cpumask> src1,
      Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_any_and_distribute((const struct cpumask*)$arg1, (const struct cpumask*)$arg2)")
  public static @Unsigned int bpf_cpumask_any_and_distribute(Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_any_distribute((const struct cpumask*)$arg1)")
  public static @Unsigned int bpf_cpumask_any_distribute(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_clear(Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_clear_cpu(@Unsigned int cpu, Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_copy($arg1, (const struct cpumask*)$arg2)")
  public static void bpf_cpumask_copy(Ptr<bpf_cpumask> dst, Ptr<cpumask> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_cpumask> bpf_cpumask_create() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_empty((const struct cpumask*)$arg1)")
  public static boolean bpf_cpumask_empty(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_equal((const struct cpumask*)$arg1, (const struct cpumask*)$arg2)")
  public static boolean bpf_cpumask_equal(Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_first((const struct cpumask*)$arg1)")
  public static @Unsigned int bpf_cpumask_first(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_first_and((const struct cpumask*)$arg1, (const struct cpumask*)$arg2)")
  public static @Unsigned int bpf_cpumask_first_and(Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_first_zero((const struct cpumask*)$arg1)")
  public static @Unsigned int bpf_cpumask_first_zero(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_full((const struct cpumask*)$arg1)")
  public static boolean bpf_cpumask_full(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_intersects((const struct cpumask*)$arg1, (const struct cpumask*)$arg2)")
  public static boolean bpf_cpumask_intersects(Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_or($arg1, (const struct cpumask*)$arg2, (const struct cpumask*)$arg3)")
  public static void bpf_cpumask_or(Ptr<bpf_cpumask> dst, Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_cpumask_populate(Ptr<cpumask> cpumask, Ptr<?> src, @Unsigned long src__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_release(Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_release_dtor(Ptr<?> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_set_cpu(@Unsigned int cpu, Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_cpumask_setall(Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_subset((const struct cpumask*)$arg1, (const struct cpumask*)$arg2)")
  public static boolean bpf_cpumask_subset(Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_cpumask_test_and_clear_cpu(@Unsigned int cpu,
      Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_cpumask_test_and_set_cpu(@Unsigned int cpu, Ptr<bpf_cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_test_cpu($arg1, (const struct cpumask*)$arg2)")
  public static boolean bpf_cpumask_test_cpu(@Unsigned int cpu, Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_weight((const struct cpumask*)$arg1)")
  public static @Unsigned int bpf_cpumask_weight(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_cpumask_xor($arg1, (const struct cpumask*)$arg2, (const struct cpumask*)$arg3)")
  public static void bpf_cpumask_xor(Ptr<bpf_cpumask> dst, Ptr<cpumask> src1, Ptr<cpumask> src2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_crypt((const struct bpf_crypto_ctx*)$arg1, (const struct bpf_dynptr_kern*)$arg2, (const struct bpf_dynptr_kern*)$arg3, (const struct bpf_dynptr_kern*)$arg4, $arg5)")
  public static int bpf_crypto_crypt(Ptr<bpf_crypto_ctx> ctx, Ptr<bpf_dynptr_kern> src,
      Ptr<bpf_dynptr_kern> dst, Ptr<bpf_dynptr_kern> siv, boolean decrypt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_crypto_ctx> bpf_crypto_ctx_acquire(Ptr<bpf_crypto_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_ctx_create((const struct bpf_crypto_params*)$arg1, $arg2, $arg3)")
  public static Ptr<bpf_crypto_ctx> bpf_crypto_ctx_create(Ptr<bpf_crypto_params> params,
      @Unsigned int params__sz, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_crypto_ctx_release(Ptr<bpf_crypto_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_decrypt($arg1, (const struct bpf_dynptr*)$arg2, (const struct bpf_dynptr*)$arg3, (const struct bpf_dynptr*)$arg4)")
  public static int bpf_crypto_decrypt(Ptr<bpf_crypto_ctx> ctx, Ptr<bpf_dynptr> src,
      Ptr<bpf_dynptr> dst, Ptr<bpf_dynptr> siv__nullable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_encrypt($arg1, (const struct bpf_dynptr*)$arg2, (const struct bpf_dynptr*)$arg3, (const struct bpf_dynptr*)$arg4)")
  public static int bpf_crypto_encrypt(Ptr<bpf_crypto_ctx> ctx, Ptr<bpf_dynptr> src,
      Ptr<bpf_dynptr> dst, Ptr<bpf_dynptr> siv__nullable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_lskcipher_alloc_tfm((const u8*)$arg1)")
  public static Ptr<?> bpf_crypto_lskcipher_alloc_tfm(String algo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_lskcipher_decrypt($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5)")
  public static int bpf_crypto_lskcipher_decrypt(Ptr<?> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> siv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_lskcipher_encrypt($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5)")
  public static int bpf_crypto_lskcipher_encrypt(Ptr<?> tfm, Ptr<java.lang.Character> src,
      Ptr<java.lang.Character> dst, @Unsigned int len, Ptr<java.lang.Character> siv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_crypto_lskcipher_free_tfm(Ptr<?> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_crypto_lskcipher_get_flags(Ptr<?> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_lskcipher_has_algo((const u8*)$arg1)")
  public static int bpf_crypto_lskcipher_has_algo(String algo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_crypto_lskcipher_ivsize(Ptr<?> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_lskcipher_setkey($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_crypto_lskcipher_setkey(Ptr<?> tfm, Ptr<java.lang.Character> key,
      @Unsigned int keylen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_crypto_lskcipher_statesize(Ptr<?> tfm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_register_type((const struct bpf_crypto_type*)$arg1)")
  public static int bpf_crypto_register_type(Ptr<bpf_crypto_type> type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_crypto_skcipher_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_crypto_skcipher_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_crypto_unregister_type((const struct bpf_crypto_type*)$arg1)")
  public static int bpf_crypto_unregister_type(Ptr<bpf_crypto_type> type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_csum_diff(@Unsigned long from, @Unsigned long from_size,
      @Unsigned long to, @Unsigned long to_size, @Unsigned long seed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_csum_level(@Unsigned long skb, @Unsigned long level,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_csum_update(@Unsigned long skb, @Unsigned long csum,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_ctx_init((const union bpf_attr*)$arg1, $arg2)")
  public static Ptr<?> bpf_ctx_init(Ptr<bpf_attr> kattr, @Unsigned int max_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_current_task_under_cgroup(@Unsigned long map, @Unsigned long idx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_d_path(@Unsigned long path, @Unsigned long buf,
      @Unsigned long sz, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_d_path_allowed((const struct bpf_prog*)$arg1)")
  public static boolean bpf_d_path_allowed(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_destroy_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_destroy_state(Ptr<lwtunnel_state> lwt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dev_bound_kfunc_check(Ptr<bpf_verifier_log> log,
      Ptr<bpf_prog_aux> prog_aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_dev_bound_kfunc_id(@Unsigned int btf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dev_bound_netdev_unregister(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_dev_bound_resolve_kfunc(Ptr<bpf_prog> prog, @Unsigned int func_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dispatcher_change_prog(Ptr<bpf_dispatcher> d, Ptr<bpf_prog> from,
      Ptr<bpf_prog> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dispatcher_nop_func((const void*)$arg1, (const struct bpf_insn*)$arg2, $arg3)")
  public static @Unsigned int bpf_dispatcher_nop_func(Ptr<?> ctx, Ptr<bpf_insn> insnsi,
      @OriginalName("bpf_func_t") Ptr<?> bpf_func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dispatcher_prepare(Ptr<bpf_dispatcher> d, Ptr<?> image, Ptr<?> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dispatcher_xdp_func((const void*)$arg1, (const struct bpf_insn*)$arg2, $arg3)")
  public static @Unsigned int bpf_dispatcher_xdp_func(Ptr<?> ctx, Ptr<bpf_insn> insnsi,
      @OriginalName("bpf_func_t") Ptr<?> bpf_func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_init(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dummy_init_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, $arg3, (const void*)$arg4)")
  public static int bpf_dummy_init_member(Ptr<btf_type> t, Ptr<btf_member> member, Ptr<?> kdata,
      Ptr<?> udata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_ops__test_1(Ptr<bpf_dummy_ops_state> cb__nullable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dummy_ops_btf_struct_access($arg1, (const struct bpf_reg_state*)$arg2, $arg3, $arg4)")
  public static int bpf_dummy_ops_btf_struct_access(Ptr<bpf_verifier_log> log,
      Ptr<bpf_reg_state> reg, int off, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dummy_ops_check_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, (const struct bpf_prog*)$arg3)")
  public static int bpf_dummy_ops_check_member(Ptr<btf_type> t, Ptr<btf_member> member,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dummy_ops_is_valid_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean bpf_dummy_ops_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_prog> prog, Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long bpf_dummy_read(Ptr<file> filp, String buf,
      @Unsigned long siz, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_reg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_struct_ops_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_test_2(Ptr<bpf_dummy_ops_state> cb, int a1, @Unsigned short a2,
      char a3, @Unsigned long a4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dummy_test_sleepable(Ptr<bpf_dummy_ops_state> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dummy_unreg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dummy_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long bpf_dummy_write(Ptr<file> filp, String buf,
      @Unsigned long siz, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_adjust((const struct bpf_dynptr*)$arg1, $arg2, $arg3)")
  public static int bpf_dynptr_adjust(Ptr<bpf_dynptr> p, @Unsigned int start, @Unsigned int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_check_size(@Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_clone((const struct bpf_dynptr*)$arg1, $arg2)")
  public static int bpf_dynptr_clone(Ptr<bpf_dynptr> p, Ptr<bpf_dynptr> clone__uninit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_copy(Ptr<bpf_dynptr> dst_ptr, @Unsigned int dst_off,
      Ptr<bpf_dynptr> src_ptr, @Unsigned int src_off, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_dynptr_data(@Unsigned long ptr, @Unsigned long offset,
      @Unsigned long len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_dynptr_from_mem(@Unsigned long data, @Unsigned long size,
      @Unsigned long flags, @Unsigned long ptr, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_from_skb(Ptr<__sk_buff> s, @Unsigned long flags,
      Ptr<bpf_dynptr> ptr__uninit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_from_skb_rdonly(Ptr<__sk_buff> skb, @Unsigned long flags,
      Ptr<bpf_dynptr> ptr__uninit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_from_xdp(Ptr<xdp_md> x, @Unsigned long flags,
      Ptr<bpf_dynptr> ptr__uninit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dynptr_init(Ptr<bpf_dynptr_kern> ptr, Ptr<?> data, bpf_dynptr_type type,
      @Unsigned int offset, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_is_null((const struct bpf_dynptr*)$arg1)")
  public static boolean bpf_dynptr_is_null(Ptr<bpf_dynptr> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_is_rdonly((const struct bpf_dynptr*)$arg1)")
  public static boolean bpf_dynptr_is_rdonly(Ptr<bpf_dynptr> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_dynptr_memset(Ptr<bpf_dynptr> p, @Unsigned int offset, @Unsigned int size,
      char val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_dynptr_read(@Unsigned long dst, @Unsigned long len,
      @Unsigned long src, @Unsigned long offset, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dynptr_set_null(Ptr<bpf_dynptr_kern> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_dynptr_set_rdonly(Ptr<bpf_dynptr_kern> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_size((const struct bpf_dynptr*)$arg1)")
  public static @Unsigned int bpf_dynptr_size(Ptr<bpf_dynptr> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_slice((const struct bpf_dynptr*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<?> bpf_dynptr_slice(Ptr<bpf_dynptr> p, @Unsigned int offset, Ptr<?> buffer__opt,
      @Unsigned int buffer__szk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_dynptr_slice_rdwr((const struct bpf_dynptr*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<?> bpf_dynptr_slice_rdwr(Ptr<bpf_dynptr> p, @Unsigned int offset,
      Ptr<?> buffer__opt, @Unsigned int buffer__szk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_dynptr_write(@Unsigned long dst, @Unsigned long offset,
      @Unsigned long src, @Unsigned long len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_encap_cmp(Ptr<lwtunnel_state> a, Ptr<lwtunnel_state> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_encap_nlsize(Ptr<lwtunnel_state> lwtstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_event_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_event_notify(Ptr<notifier_block> nb, @Unsigned long op, Ptr<?> module) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_event_output(Ptr<bpf_map> map, @Unsigned long flags, Ptr<?> meta,
      @Unsigned long meta_size, Ptr<?> ctx, @Unsigned long ctx_size,
      @OriginalName("bpf_ctx_copy_t") Ptr<?> ctx_copy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_event_output_data(@Unsigned long ctx, @Unsigned long map,
      @Unsigned long flags, @Unsigned long data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_array_map_lookup_elem(Ptr<bpf_map> map, Ptr<?> key,
      Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_array_map_update_elem(Ptr<bpf_map> map, Ptr<file> map_file, Ptr<?> key,
      Ptr<?> value, @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_htab_map_lookup_elem(Ptr<bpf_map> map, Ptr<?> key,
      Ptr<java.lang. @Unsigned Integer> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_htab_map_update_elem(Ptr<bpf_map> map, Ptr<file> map_file, Ptr<?> key,
      Ptr<?> value, @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_fd_inode_storage_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_fd_inode_storage_lookup_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_fd_inode_storage_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_fd_pass((const struct file*)$arg1, $arg2)")
  public static int bpf_fd_pass(Ptr<file> file, @Unsigned int sid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_reuseport_array_lookup_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fd_reuseport_array_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_fd_sk_storage_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_fd_sk_storage_lookup_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_fd_sk_storage_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_shadow_test(int a) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test1(int a) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_fentry_test10((const void*)$arg1)")
  public static int bpf_fentry_test10(Ptr<?> a) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test2(int a, @Unsigned long b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test3(char a, int b, @Unsigned long c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test4(Ptr<?> a, char b, int c, @Unsigned long d) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test5(@Unsigned long a, Ptr<?> b, short c, int d, @Unsigned long e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test6(@Unsigned long a, Ptr<?> b, short c, int d, Ptr<?> e,
      @Unsigned long f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test7(Ptr<bpf_fentry_test_t> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fentry_test8(Ptr<bpf_fentry_test_t> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_fentry_test9(Ptr<java.lang. @Unsigned Integer> a) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_fentry_test_sinfo(Ptr<skb_shared_info> sinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fill_encap_info(Ptr<sk_buff> skb, Ptr<lwtunnel_state> lwt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fill_lwt_prog(Ptr<sk_buff> skb, int attr, Ptr<bpf_lwt_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fill_super(Ptr<super_block> sb, Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_find_btf_id((const u8*)$arg1, $arg2, $arg3)")
  public static int bpf_find_btf_id(String name, @Unsigned int kind, Ptr<Ptr<btf>> btf_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_find_exception_callback_insn_off(Ptr<bpf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_find_vma(@Unsigned long task, @Unsigned long start,
      @Unsigned long callback_fn, @Unsigned long callback_ctx, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_flow_dissect(Ptr<bpf_prog> prog, Ptr<bpf_flow_dissector> ctx,
      @Unsigned @OriginalName("__be16") short proto, int nhoff, int hlen, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_flow_dissector_load_bytes(@Unsigned long ctx,
      @Unsigned long offset, @Unsigned long to, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_for_each_array_elem(Ptr<bpf_map> map,
      @OriginalName("bpf_callback_t") Ptr<?> callback_fn, Ptr<?> callback_ctx,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_for_each_hash_elem(Ptr<bpf_map> map,
      @OriginalName("bpf_callback_t") Ptr<?> callback_fn, Ptr<?> callback_ctx,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_for_each_map_elem(@Unsigned long map, @Unsigned long callback_fn,
      @Unsigned long callback_ctx, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_free_fc(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_free_kfunc_btf_tab(Ptr<bpf_kfunc_btf_tab> tab) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_fs_kfuncs_filter((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_fs_kfuncs_filter(Ptr<bpf_prog> prog, @Unsigned int kfunc_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_fs_kfuncs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_gen_ld_abs((const struct bpf_insn*)$arg1, $arg2)")
  public static int bpf_gen_ld_abs(Ptr<bpf_insn> orig, Ptr<bpf_insn> insn_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie(@Unsigned long ctx, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie_kprobe_multi(@Unsigned long regs,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie_pe(@Unsigned long ctx, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie_trace(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie_tracing(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_attach_cookie_uprobe_multi(@Unsigned long regs,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_branch_snapshot(@Unsigned long buf, @Unsigned long size,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<btf> bpf_get_btf_vmlinux() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_cgroup_classid(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_cgroup_classid_curr(@Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_ancestor_cgroup_id(@Unsigned long ancestor_level,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_cgroup_id(@Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_comm(@Unsigned long buf, @Unsigned long size,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_pid_tgid(@Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_task(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_task_btf(@Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_current_uid_gid(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_dentry_xattr($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_get_dentry_xattr(Ptr<dentry> dentry, String name__str,
      Ptr<bpf_dynptr> value_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_get_file_flag(int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_file_xattr($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_get_file_xattr(Ptr<file> file, String name__str, Ptr<bpf_dynptr> value_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_get_fsverity_digest(Ptr<file> file, Ptr<bpf_dynptr> digest_p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_fsverity_digest_filter((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_get_fsverity_digest_filter(Ptr<bpf_prog> prog, @Unsigned int kfunc_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_func_ip_kprobe(@Unsigned long regs, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_func_ip_kprobe_multi(@Unsigned long regs,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_func_ip_tracing(@Unsigned long ctx, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_func_ip_uprobe_multi(@Unsigned long regs,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_hash_recalc(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_inode($arg1, (const struct inode*)$arg2, $arg3)")
  public static Ptr<inode> bpf_get_inode(Ptr<super_block> sb, Ptr<inode> dir,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_get_kallsym(@Unsigned int symnum, Ptr<java.lang. @Unsigned Long> value,
      String type, String sym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_kfunc_addr((const struct bpf_prog*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_get_kfunc_addr(Ptr<bpf_prog> prog, @Unsigned int func_id,
      @Unsigned short btf_fd_idx, Ptr<Ptr<java.lang.Character>> func_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<kmem_cache> bpf_get_kmem_cache(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_kprobe_info((const struct perf_event*)$arg1, $arg2, (const u8**)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int bpf_get_kprobe_info(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Integer> fd_type, Ptr<String> symbol,
      Ptr<java.lang. @Unsigned Long> probe_offset, Ptr<java.lang. @Unsigned Long> probe_addr,
      Ptr<java.lang. @Unsigned Long> missed, boolean perf_type_tracepoint) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_listener_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_local_storage(@Unsigned long map, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie_sk_msg(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie_sock(@Unsigned long ctx, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie_sock_addr(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie_sock_ops(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_netns_cookie_sockopt(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_ns_current_pid_tgid(@Unsigned long dev, @Unsigned long ino,
      @Unsigned long nsdata, @Unsigned long size, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_numa_node_id(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_perf_event_info((const struct perf_event*)$arg1, $arg2, $arg3, (const u8**)$arg4, $arg5, $arg6, $arg7)")
  public static int bpf_get_perf_event_info(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Integer> prog_id, Ptr<java.lang. @Unsigned Integer> fd_type,
      Ptr<String> buf, Ptr<java.lang. @Unsigned Long> probe_offset,
      Ptr<java.lang. @Unsigned Long> probe_addr, Ptr<java.lang. @Unsigned Long> missed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_get_perf_event_read_value_proto())")
  public static Ptr<bpf_func_proto> bpf_get_perf_event_read_value_proto() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_raw_cpu_id(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_raw_tracepoint((const u8*)$arg1)")
  public static Ptr<bpf_raw_event_map> bpf_get_raw_tracepoint(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_retval(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_route_realm(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_get_skb_set_tunnel_proto($arg1))")
  public static Ptr<bpf_func_proto> bpf_get_skb_set_tunnel_proto(bpf_func_id which) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_smp_processor_id(@Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_cookie(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_cookie_sock(@Unsigned long ctx, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_cookie_sock_addr(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_cookie_sock_ops(@Unsigned long ctx,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_ptr_cookie(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_socket_uid(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stack(@Unsigned long regs, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stack_pe(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stack_raw_tp(@Unsigned long args, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stack_sleepable(@Unsigned long regs, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stack_tp(@Unsigned long tp_buff, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stackid(@Unsigned long regs, @Unsigned long map,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stackid_pe(@Unsigned long ctx, @Unsigned long map,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stackid_raw_tp(@Unsigned long args, @Unsigned long map,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_stackid_tp(@Unsigned long tp_buff, @Unsigned long map,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> bpf_get_task_exe_file(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_task_stack(@Unsigned long task, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_task_stack_sleepable(@Unsigned long task, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_get_trace_printk_proto())")
  public static Ptr<bpf_func_proto> bpf_get_trace_printk_proto() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_get_trace_vprintk_proto())")
  public static Ptr<bpf_func_proto> bpf_get_trace_vprintk_proto() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_get_tree(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_get_unmapped_area(Ptr<file> filp, @Unsigned long addr,
      @Unsigned long len, @Unsigned long pgoff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_get_uprobe_info((const struct perf_event*)$arg1, $arg2, (const u8**)$arg3, $arg4, $arg5, $arg6)")
  public static int bpf_get_uprobe_info(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Integer> fd_type, Ptr<String> filename,
      Ptr<java.lang. @Unsigned Long> probe_offset, Ptr<java.lang. @Unsigned Long> probe_addr,
      boolean perf_type_tracepoint) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_global_ma_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<htab_elem> bpf_hash_map_seq_find_next(Ptr<bpf_iter_seq_hash_map_info> info,
      Ptr<htab_elem> prev_elem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_hash_map_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_hash_map_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_hash_map_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_hash_map_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_helper_changes_pkt_data(bpf_func_id func_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ima_file_hash(@Unsigned long file, @Unsigned long dst,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ima_inode_hash(@Unsigned long inode, @Unsigned long dst,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_ima_inode_hash_allowed((const struct bpf_prog*)$arg1)")
  public static boolean bpf_ima_inode_hash_allowed(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_image_ksym_add(Ptr<bpf_ksym> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_image_ksym_del(Ptr<bpf_ksym> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_image_ksym_init(Ptr<?> data, @Unsigned int size, Ptr<bpf_ksym> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_init_fs_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_inode_storage_delete(@Unsigned long map, @Unsigned long inode,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_inode_storage_free(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_inode_storage_get(@Unsigned long map, @Unsigned long inode,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_input(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_insn_prepare_dump((const struct bpf_prog*)$arg1, (const struct cred*)$arg2)")
  public static Ptr<bpf_insn> bpf_insn_prepare_dump(Ptr<bpf_prog> prog, Ptr<cred> f_cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_int_jit_compile(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_internal_load_pointer_neg_helper((const struct sk_buff*)$arg1, $arg2, $arg3)")
  public static Ptr<?> bpf_internal_load_pointer_neg_helper(Ptr<sk_buff> skb, int k,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_ipv4_fib_lookup(Ptr<net> net, Ptr<bpf_fib_lookup> params,
      @Unsigned int flags, boolean check_mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_ipv6_fib_lookup(Ptr<net> net, Ptr<bpf_fib_lookup> params,
      @Unsigned int flags, boolean check_mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_attach_cgroup(Ptr<bpf_prog> prog, Ptr<bpf_iter_link_info> linfo,
      Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_attach_map(Ptr<bpf_prog> prog, Ptr<bpf_iter_link_info> linfo,
      Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_attach_task(Ptr<bpf_prog> prog, Ptr<bpf_iter_link_info> linfo,
      Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_bits_destroy(Ptr<bpf_iter_bits> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_bits_new($arg1, (const long long unsigned int*)$arg2, $arg3)")
  public static int bpf_iter_bits_new(Ptr<bpf_iter_bits> it,
      Ptr<java.lang. @Unsigned Long> unsafe_ptr__ign, @Unsigned int nr_words) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang.Integer> bpf_iter_bits_next(Ptr<bpf_iter_bits> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_bpf_link(Ptr<bpf_iter_meta> meta, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_bpf_map(Ptr<bpf_iter_meta> meta, Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_bpf_map_elem(Ptr<bpf_iter_meta> meta, Ptr<bpf_map> map, Ptr<?> key,
      Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_bpf_prog(Ptr<bpf_iter_meta> meta, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_bpf_sk_storage_map(Ptr<bpf_iter_meta> meta, Ptr<bpf_map> map,
      Ptr<sock> sk, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_cgroup(Ptr<bpf_iter_meta> meta, Ptr<cgroup> cgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_cgroup_fill_link_info((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static int bpf_iter_cgroup_fill_link_info(Ptr<bpf_iter_aux_info> aux,
      Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_cgroup_show_fdinfo((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static void bpf_iter_cgroup_show_fdinfo(Ptr<bpf_iter_aux_info> aux, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_css_destroy(Ptr<bpf_iter_css> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_css_new(Ptr<bpf_iter_css> it, Ptr<cgroup_subsys_state> start,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup_subsys_state> bpf_iter_css_next(Ptr<bpf_iter_css> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_css_task_destroy(Ptr<bpf_iter_css_task> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_css_task_new(Ptr<bpf_iter_css_task> it, Ptr<cgroup_subsys_state> css,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_iter_css_task_next(Ptr<bpf_iter_css_task> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_detach_cgroup(Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_detach_map(Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_dmabuf_destroy(Ptr<bpf_iter_dmabuf> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_dmabuf_new(Ptr<bpf_iter_dmabuf> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> bpf_iter_dmabuf_next(Ptr<bpf_iter_dmabuf> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_dmabuf_show_fdinfo((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static void bpf_iter_dmabuf_show_fdinfo(Ptr<bpf_iter_aux_info> aux, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_fill_link_info((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static int bpf_iter_fill_link_info(Ptr<bpf_iter_aux_info> aux, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_array_map(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_hash_map(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_seq_net(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_sk_storage_map(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_tcp(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_udp(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_fini_unix(Ptr<?> priv_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_iter_get_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_iter_get_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_iter_get_info(Ptr<bpf_iter_meta> meta, boolean in_stop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_array_map(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_hash_map(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_seq_net(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_sk_storage_map(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_tcp(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_udp(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_init_unix(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_ipv6_route(Ptr<bpf_iter_meta> meta, Ptr<fib6_info> rt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_kmem_cache_destroy(Ptr<bpf_iter_kmem_cache> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_kmem_cache_new(Ptr<bpf_iter_kmem_cache> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<kmem_cache> bpf_iter_kmem_cache_next(Ptr<bpf_iter_kmem_cache> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_kmem_cache_show_fdinfo((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static void bpf_iter_kmem_cache_show_fdinfo(Ptr<bpf_iter_aux_info> aux,
      Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_ksym(Ptr<bpf_iter_meta> meta, Ptr<kallsym_iter> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_ksym_init(Ptr<?> priv_data, Ptr<bpf_iter_aux_info> aux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_ksym_seq_show(Ptr<seq_file> m, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_ksym_seq_stop(Ptr<seq_file> m, Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_link_attach((const union bpf_attr*)$arg1, $arg2, $arg3)")
  public static int bpf_iter_link_attach(Ptr<bpf_attr> attr,
      @OriginalName("bpfptr_t") sockptr_t uattr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_iter_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_link_replace(Ptr<bpf_link> link, Ptr<bpf_prog> new_prog,
      Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_iter_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_map_fill_link_info((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static int bpf_iter_map_fill_link_info(Ptr<bpf_iter_aux_info> aux,
      Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_map_show_fdinfo((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static void bpf_iter_map_show_fdinfo(Ptr<bpf_iter_aux_info> aux, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_netlink(Ptr<bpf_iter_meta> meta, Ptr<netlink_sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_new_fd(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_num_destroy(Ptr<bpf_iter_num> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_num_new(Ptr<bpf_iter_num> it, int start, int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang.Integer> bpf_iter_num_next(Ptr<bpf_iter_num> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_prog_supported(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_reg_target((const struct bpf_iter_reg*)$arg1)")
  public static int bpf_iter_reg_target(Ptr<bpf_iter_reg> reg_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_run_prog(Ptr<bpf_prog> prog, Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_scx_dsq_destroy(Ptr<bpf_iter_scx_dsq> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_scx_dsq_new(Ptr<bpf_iter_scx_dsq> it, @Unsigned long dsq_id,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_iter_scx_dsq_next(Ptr<bpf_iter_scx_dsq> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_sockmap(Ptr<bpf_iter_meta> meta, Ptr<bpf_map> map, Ptr<?> key,
      Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_task_destroy(Ptr<bpf_iter_task> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_task_file(Ptr<bpf_iter_meta> meta, Ptr<task_struct> task,
      @Unsigned int fd, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_task_new(Ptr<bpf_iter_task> it, Ptr<task_struct> task__nullable,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_iter_task_next(Ptr<bpf_iter_task> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_task_show_fdinfo((const struct bpf_iter_aux_info*)$arg1, $arg2)")
  public static void bpf_iter_task_show_fdinfo(Ptr<bpf_iter_aux_info> aux, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_task_vma_destroy(Ptr<bpf_iter_task_vma> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_task_vma_new(Ptr<bpf_iter_task_vma> it, Ptr<task_struct> task,
      @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vm_area_struct> bpf_iter_task_vma_next(Ptr<bpf_iter_task_vma> it) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_tcp(Ptr<bpf_iter_meta> meta, Ptr<sock_common> sk_common,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> bpf_iter_tcp_batch(Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_iter_tcp_established_batch(Ptr<seq_file> seq,
      Ptr<Ptr<sock>> start_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_iter_tcp_get_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_iter_tcp_get_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_iter_tcp_listening_batch(Ptr<seq_file> seq,
      Ptr<Ptr<sock>> start_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_tcp_put_batch(Ptr<bpf_tcp_iter_state> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_tcp_realloc_batch(Ptr<bpf_tcp_iter_state> iter,
      @Unsigned int new_batch_sz, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> bpf_iter_tcp_resume(Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_tcp_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_tcp_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_tcp_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_tcp_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_tcp_unlock_bucket(Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_udp(Ptr<bpf_iter_meta> meta, Ptr<udp_sock> udp_sk,
      @Unsigned @OriginalName("uid_t") int uid, int bucket) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> bpf_iter_udp_batch(Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_udp_put_batch(Ptr<bpf_udp_iter_state> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_udp_realloc_batch(Ptr<bpf_udp_iter_state> iter,
      @Unsigned int new_batch_sz, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_udp_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_udp_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_udp_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_udp_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_unix(Ptr<bpf_iter_meta> meta, Ptr<unix_sock> unix_sk,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> bpf_iter_unix_batch(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_iter_unix_get_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_iter_unix_get_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_unix_realloc_batch(Ptr<bpf_unix_iter_state> iter,
      @Unsigned int new_batch_sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_unix_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_iter_unix_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_iter_unix_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_iter_unix_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_iter_unreg_target((const struct bpf_iter_reg*)$arg1)")
  public static void bpf_iter_unreg_target(Ptr<bpf_iter_reg> reg_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_jiffies64(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_jit_add_poke_descriptor(Ptr<bpf_prog> prog,
      Ptr<bpf_jit_poke_descriptor> poke) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_jit_alloc_exec(@Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_jit_alloc_exec_limit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_binary_header> bpf_jit_binary_alloc(@Unsigned int proglen,
      Ptr<Ptr<java.lang.Character>> image_ptr, @Unsigned int alignment,
      @OriginalName("bpf_jit_fill_hole_t") Ptr<?> bpf_fill_ill_insns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_binary_free(Ptr<bpf_binary_header> hdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_binary_header> bpf_jit_binary_pack_alloc(@Unsigned int proglen,
      Ptr<Ptr<java.lang.Character>> image_ptr, @Unsigned int alignment,
      Ptr<Ptr<bpf_binary_header>> rw_header, Ptr<Ptr<java.lang.Character>> rw_image,
      @OriginalName("bpf_jit_fill_hole_t") Ptr<?> bpf_fill_ill_insns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_jit_binary_pack_finalize(Ptr<bpf_binary_header> ro_header,
      Ptr<bpf_binary_header> rw_header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_binary_pack_free(Ptr<bpf_binary_header> ro_header,
      Ptr<bpf_binary_header> rw_header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_jit_binary_pack_hdr((const struct bpf_prog*)$arg1)")
  public static Ptr<bpf_binary_header> bpf_jit_binary_pack_hdr(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_jit_blind_constants(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_jit_blind_insn((const struct bpf_insn*)$arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4)")
  public static int bpf_jit_blind_insn(Ptr<bpf_insn> from, Ptr<bpf_insn> aux, Ptr<bpf_insn> to_buff,
      boolean emit_zext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_bypass_spec_v1() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_bypass_spec_v4() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_jit_charge_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_jit_charge_modmem(@Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_compile(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_fill_hole_with_zero(Ptr<?> area, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct btf_func_model*)bpf_jit_find_kfunc_model((const struct bpf_prog*)$arg1, (const struct bpf_insn*)$arg2))")
  public static Ptr<btf_func_model> bpf_jit_find_kfunc_model(Ptr<bpf_prog> prog,
      Ptr<bpf_insn> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_free(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_free_exec(Ptr<?> addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_jit_get_func_addr((const struct bpf_prog*)$arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static int bpf_jit_get_func_addr(Ptr<bpf_prog> prog, Ptr<bpf_insn> insn,
      boolean extra_pass, Ptr<java.lang. @Unsigned Long> func_addr,
      Ptr<java.lang. @OriginalName("bool") Boolean> func_addr_fixed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)bpf_jit_get_prog_name($arg1))")
  public static String bpf_jit_get_prog_name(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_inlines_helper_call(int imm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_needs_zext() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_prog_release_other(Ptr<bpf_prog> fp, Ptr<bpf_prog> fp_other) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_arena() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_exceptions() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_far_kfunc_call() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_insn(Ptr<bpf_insn> insn, boolean in_arena) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_kfunc_call() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_percpu_insn() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_private_stack() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_ptr_xchg() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_subprog_tailcalls() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_jit_supports_timed_may_goto() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_jit_uncharge_modmem(@Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_kallsyms_lookup_name(@Unsigned long name, @Unsigned long name_sz,
      @Unsigned long flags, @Unsigned long res, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_key_put(Ptr<bpf_key> bkey) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_key_sig_kfuncs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kfree_skb(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kfunc_call_memb_release(Ptr<prog_test_member> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kfunc_call_memb_release_dtor(Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kfunc_call_test_release(Ptr<prog_test_ref_kfunc> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kfunc_call_test_release_dtor(Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kill_super(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_kmem_cache_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_addrs_cmp((const void*)$arg1, (const void*)$arg2)")
  public static int bpf_kprobe_multi_addrs_cmp(Ptr<?> a, Ptr<?> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_cookie_cmp((const void*)$arg1, (const void*)$arg2, (const void*)$arg3)")
  public static int bpf_kprobe_multi_cookie_cmp(Ptr<?> a, Ptr<?> b, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_cookie_swap($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static void bpf_kprobe_multi_cookie_swap(Ptr<?> a, Ptr<?> b, int size, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_filter((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_kprobe_multi_filter(Ptr<bpf_prog> prog, @Unsigned int kfunc_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_kprobe_multi_kfuncs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_link_attach((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_kprobe_multi_link_attach(Ptr<bpf_attr> attr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kprobe_multi_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_kprobe_multi_link_fill_link_info(Ptr<bpf_link> link,
      Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_kprobe_multi_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_kprobe_multi_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_kprobe_multi_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_kptr_xchg(@Unsigned long dst, @Unsigned long ptr,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ksym_add(Ptr<bpf_ksym> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ksym_del(Ptr<bpf_ksym> ksym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_ksym> bpf_ksym_find(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_ksym_iter_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_boot_ns(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_coarse_ns(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_ns(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ktime_get_tai_ns(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_l3_csum_replace(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long from, @Unsigned long to, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_l4_csum_replace(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long from, @Unsigned long to, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_link> bpf_link_by_id(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_cleanup(Ptr<bpf_link_primer> primer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_defer_dealloc_mult_rcu_gp(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_defer_dealloc_rcu_gp(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_free(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_link> bpf_link_get_curr_or_next(Ptr<java.lang. @Unsigned Integer> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_link> bpf_link_get_from_fd(@Unsigned int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_inc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_link> bpf_link_inc_not_zero(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_link_init($arg1, $arg2, (const struct bpf_link_ops*)$arg3, $arg4, $arg5)")
  public static void bpf_link_init(Ptr<bpf_link> link, bpf_link_type type, Ptr<bpf_link_ops> ops,
      Ptr<bpf_prog> prog, bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_link_init_sleepable($arg1, $arg2, (const struct bpf_link_ops*)$arg3, $arg4, $arg5, $arg6)")
  public static void bpf_link_init_sleepable(Ptr<bpf_link> link, bpf_link_type type,
      Ptr<bpf_link_ops> ops, Ptr<bpf_prog> prog, bpf_attach_type attach_type, boolean sleepable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_link_is_iter(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_new_fd(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int bpf_link_poll(Ptr<file> file,
      Ptr<poll_table_struct> pts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_prime(Ptr<bpf_link> link, Ptr<bpf_link_primer> primer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_put(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_put_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_link_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_link_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_link_settle(Ptr<bpf_link_primer> primer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_link_show_fdinfo(Ptr<seq_file> m, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_list_node> bpf_list_back(Ptr<bpf_list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_list_node> bpf_list_front(Ptr<bpf_list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_list_head_free((const struct btf_field*)$arg1, $arg2, $arg3)")
  public static void bpf_list_head_free(Ptr<btf_field> field, Ptr<?> list_head,
      Ptr<bpf_spin_lock> spin_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_list_node> bpf_list_pop_back(Ptr<bpf_list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_list_node> bpf_list_pop_front(Ptr<bpf_list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_list_push_back_impl(Ptr<bpf_list_head> head, Ptr<bpf_list_node> node,
      Ptr<?> meta__ign, @Unsigned long off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_list_push_front_impl(Ptr<bpf_list_head> head, Ptr<bpf_list_node> node,
      Ptr<?> meta__ign, @Unsigned long off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_irq_restore(Ptr<java.lang. @Unsigned Long> flags__irq_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_irq_save(Ptr<java.lang. @Unsigned Long> flags__irq_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_local_storage_alloc(Ptr<?> owner, Ptr<bpf_local_storage_map> smap,
      Ptr<bpf_local_storage_elem> first_selem, @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_storage_destroy(Ptr<bpf_local_storage> local_storage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_storage_free(Ptr<bpf_local_storage> local_storage,
      Ptr<bpf_local_storage_map> smap, boolean bpf_ma, boolean reuse_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_storage_free_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_storage_free_trace_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_local_storage_map_alloc(Ptr<bpf_attr> attr,
      Ptr<bpf_local_storage_cache> cache, boolean bpf_ma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_local_storage_map_alloc_check(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_local_storage_map_check_btf((const struct bpf_map*)$arg1, (const struct btf*)$arg2, (const struct btf_type*)$arg3, (const struct btf_type*)$arg4)")
  public static int bpf_local_storage_map_check_btf(Ptr<bpf_map> map, Ptr<btf> btf,
      Ptr<btf_type> key_type, Ptr<btf_type> value_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_local_storage_map_free(Ptr<bpf_map> map,
      Ptr<bpf_local_storage_cache> cache, Ptr<java.lang.Integer> busy_counter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_local_storage_map_mem_usage((const struct bpf_map*)$arg1)")
  public static @Unsigned long bpf_local_storage_map_mem_usage(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_local_storage_data> bpf_local_storage_update(Ptr<?> owner,
      Ptr<bpf_local_storage_map> smap, Ptr<?> value, @Unsigned long map_flags, boolean swap_uptrs,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_log($arg1, (const u8*)$arg2, $arg3_)")
  public static void bpf_log(Ptr<bpf_verifier_log> log, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> bpf_lookup(Ptr<inode> dir, Ptr<dentry> dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_key> bpf_lookup_system_key(@Unsigned long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_key> bpf_lookup_user_key(int serial, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_loop(@Unsigned long nr_loops, @Unsigned long callback_fn,
      @Unsigned long callback_ctx, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lru_destroy(Ptr<bpf_lru> lru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lru_init(Ptr<bpf_lru> lru, boolean percpu, @Unsigned int hash_offset,
      @OriginalName("del_from_htab_func") Ptr<?> del_from_htab, Ptr<?> del_arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_lru_node> bpf_lru_pop_free(Ptr<bpf_lru> lru, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lru_populate(Ptr<bpf_lru> lru, Ptr<?> buf, @Unsigned int node_offset,
      @Unsigned int elem_size, @Unsigned int nr_elems) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lru_push_free(Ptr<bpf_lru> lru, Ptr<bpf_lru_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_audit_rule_free(Ptr<?> lsmrule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_audit_rule_init(@Unsigned int field, @Unsigned int op, String rulestr,
      Ptr<Ptr<?>> lsmrule, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_audit_rule_known(Ptr<audit_krule> krule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_audit_rule_match(Ptr<lsm_prop> prop, @Unsigned int field,
      @Unsigned int op, Ptr<?> lsmrule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bdev_alloc_security(Ptr<block_device> bdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_bdev_free_security(Ptr<block_device> bdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bdev_setintegrity($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static int bpf_lsm_bdev_setintegrity(Ptr<block_device> bdev, lsm_integrity_type type,
      Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_binder_set_context_mgr((const struct cred*)$arg1)")
  public static int bpf_lsm_binder_set_context_mgr(Ptr<cred> mgr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_binder_transaction((const struct cred*)$arg1, (const struct cred*)$arg2)")
  public static int bpf_lsm_binder_transaction(Ptr<cred> from, Ptr<cred> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_binder_transfer_binder((const struct cred*)$arg1, (const struct cred*)$arg2)")
  public static int bpf_lsm_binder_transfer_binder(Ptr<cred> from, Ptr<cred> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_binder_transfer_file((const struct cred*)$arg1, (const struct cred*)$arg2, (const struct file*)$arg3)")
  public static int bpf_lsm_binder_transfer_file(Ptr<cred> from, Ptr<cred> to, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bpf(int cmd, Ptr<bpf_attr> attr, @Unsigned int size, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bpf_map(Ptr<bpf_map> map,
      @Unsigned @OriginalName("fmode_t") int fmode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bpf_map_create(Ptr<bpf_map> map, Ptr<bpf_attr> attr,
      Ptr<bpf_token> token, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_bpf_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bpf_prog(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_bpf_prog_free(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bpf_prog_load(Ptr<bpf_prog> prog, Ptr<bpf_attr> attr,
      Ptr<bpf_token> token, boolean kernel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bpf_token_capable((const struct bpf_token*)$arg1, $arg2)")
  public static int bpf_lsm_bpf_token_capable(Ptr<bpf_token> token, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bpf_token_cmd((const struct bpf_token*)$arg1, $arg2)")
  public static int bpf_lsm_bpf_token_cmd(Ptr<bpf_token> token, bpf_cmd cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bpf_token_create($arg1, $arg2, (const struct path*)$arg3)")
  public static int bpf_lsm_bpf_token_create(Ptr<bpf_token> token, Ptr<bpf_attr> attr,
      Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_bpf_token_free(Ptr<bpf_token> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bprm_check_security(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bprm_committed_creds((const struct linux_binprm*)$arg1)")
  public static void bpf_lsm_bprm_committed_creds(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bprm_committing_creds((const struct linux_binprm*)$arg1)")
  public static void bpf_lsm_bprm_committing_creds(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_bprm_creds_for_exec(Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_bprm_creds_from_file($arg1, (const struct file*)$arg2)")
  public static int bpf_lsm_bprm_creds_from_file(Ptr<linux_binprm> bprm, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_capable((const struct cred*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_lsm_capable(Ptr<cred> cred, Ptr<user_namespace> ns, int cap,
      @Unsigned int opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_capget((const struct task_struct*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_lsm_capget(Ptr<task_struct> target, Ptr<kernel_cap_t> effective,
      Ptr<kernel_cap_t> inheritable, Ptr<kernel_cap_t> permitted) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_capset($arg1, (const struct cred*)$arg2, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "}*)$arg3, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "}*)$arg4, (const struct {\n"
          + "  long long unsigned int val;\n"
          + "}*)$arg5)")
  public static int bpf_lsm_capset(Ptr<cred> _new, Ptr<cred> old, Ptr<kernel_cap_t> effective,
      Ptr<kernel_cap_t> inheritable, Ptr<kernel_cap_t> permitted) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_cred_alloc_blank(Ptr<cred> cred,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_cred_free(Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_cred_getlsmprop((const struct cred*)$arg1, $arg2)")
  public static void bpf_lsm_cred_getlsmprop(Ptr<cred> c, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_cred_getsecid((const struct cred*)$arg1, $arg2)")
  public static void bpf_lsm_cred_getsecid(Ptr<cred> c, Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_cred_prepare($arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_cred_prepare(Ptr<cred> _new, Ptr<cred> old,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_cred_transfer($arg1, (const struct cred*)$arg2)")
  public static void bpf_lsm_cred_transfer(Ptr<cred> _new, Ptr<cred> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_current_getlsmprop_subj(Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_d_instantiate(Ptr<dentry> dentry, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_dentry_create_files_as($arg1, $arg2, $arg3, (const struct cred*)$arg4, $arg5)")
  public static int bpf_lsm_dentry_create_files_as(Ptr<dentry> dentry, int mode, Ptr<qstr> name,
      Ptr<cred> old, Ptr<cred> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_dentry_init_security($arg1, $arg2, (const struct qstr*)$arg3, (const u8**)$arg4, $arg5)")
  public static int bpf_lsm_dentry_init_security(Ptr<dentry> dentry, int mode, Ptr<qstr> name,
      Ptr<String> xattr_name, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_alloc_security(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_fcntl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_file_free_security(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_ioctl_compat(Ptr<file> file, @Unsigned int cmd,
      @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_lock(Ptr<file> file, @Unsigned int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_mprotect(Ptr<vm_area_struct> vma, @Unsigned long reqprot,
      @Unsigned long prot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_open(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_permission(Ptr<file> file, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_post_open(Ptr<file> file, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_receive(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_file_release(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_send_sigiotask(Ptr<task_struct> tsk, Ptr<fown_struct> fown,
      int sig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_file_set_fowner(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_file_truncate(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_find_cgroup_shim((const struct bpf_prog*)$arg1, $arg2)")
  public static void bpf_lsm_find_cgroup_shim(Ptr<bpf_prog> prog,
      Ptr<@OriginalName("bpf_func_t") Ptr<?>> bpf_func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_fs_context_dup(Ptr<fs_context> fc, Ptr<fs_context> src_sc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_fs_context_parse_param(Ptr<fs_context> fc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_fs_context_submount(Ptr<fs_context> fc, Ptr<super_block> reference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_lsm_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_lsm_func_proto(bpf_func_id func_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_get_retval_range((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_lsm_get_retval_range(Ptr<bpf_prog> prog,
      Ptr<bpf_retval_range> retval_range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_getprocattr($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_lsm_getprocattr(Ptr<task_struct> p, String name, Ptr<String> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_getselfattr(@Unsigned int attr, Ptr<lsm_ctx> ctx,
      Ptr<java.lang. @Unsigned Integer> size, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_has_d_inode_locked((const struct bpf_prog*)$arg1)")
  public static boolean bpf_lsm_has_d_inode_locked(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_ib_alloc_security(Ptr<?> sec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_ib_endport_manage_subnet($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_lsm_ib_endport_manage_subnet(Ptr<?> sec, String dev_name, char port_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_ib_pkey_access(Ptr<?> sec, @Unsigned long subnet_prefix,
      @Unsigned short pkey) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inet_conn_established(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inet_conn_request((const struct sock*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_inet_conn_request(Ptr<sock> sk, Ptr<sk_buff> skb,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inet_csk_clone($arg1, (const struct request_sock*)$arg2)")
  public static void bpf_lsm_inet_csk_clone(Ptr<sock> newsk, Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_initramfs_populated() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_alloc_security(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_copy_up(Ptr<dentry> src, Ptr<Ptr<cred>> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_copy_up_xattr($arg1, (const u8*)$arg2)")
  public static int bpf_lsm_inode_copy_up_xattr(Ptr<dentry> src, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_create(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_file_getattr(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_file_setattr(Ptr<dentry> dentry, Ptr<file_kattr> fa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_follow_link(Ptr<dentry> dentry, Ptr<inode> inode, boolean rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_free_security(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_free_security_rcu(Ptr<?> inode_security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_get_acl($arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_lsm_inode_get_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_getattr((const struct path*)$arg1)")
  public static int bpf_lsm_inode_getattr(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_getlsmprop(Ptr<inode> inode, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_getsecctx(Ptr<inode> inode, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_getsecurity($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int bpf_lsm_inode_getsecurity(Ptr<mnt_idmap> idmap, Ptr<inode> inode, String name,
      Ptr<Ptr<?>> buffer, boolean alloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_getxattr($arg1, (const u8*)$arg2)")
  public static int bpf_lsm_inode_getxattr(Ptr<dentry> dentry, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_init_security($arg1, $arg2, (const struct qstr*)$arg3, $arg4, $arg5)")
  public static int bpf_lsm_inode_init_security(Ptr<inode> inode, Ptr<inode> dir, Ptr<qstr> qstr,
      Ptr<xattr> xattrs, Ptr<java.lang.Integer> xattr_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_init_security_anon($arg1, (const struct qstr*)$arg2, (const struct inode*)$arg3)")
  public static int bpf_lsm_inode_init_security_anon(Ptr<inode> inode, Ptr<qstr> name,
      Ptr<inode> context_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_invalidate_secctx(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_killpriv(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_link(Ptr<dentry> old_dentry, Ptr<inode> dir,
      Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_listsecurity(Ptr<inode> inode, String buffer,
      @Unsigned long buffer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_listxattr(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_mkdir(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_mknod(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned @OriginalName("dev_t") int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_need_killpriv(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_notifysecctx(Ptr<inode> inode, Ptr<?> ctx, @Unsigned int ctxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_permission(Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_post_create_tmpfile(Ptr<mnt_idmap> idmap, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_post_remove_acl($arg1, $arg2, (const u8*)$arg3)")
  public static void bpf_lsm_inode_post_remove_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_post_removexattr($arg1, (const u8*)$arg2)")
  public static void bpf_lsm_inode_post_removexattr(Ptr<dentry> dentry, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_post_set_acl($arg1, (const u8*)$arg2, $arg3)")
  public static void bpf_lsm_inode_post_set_acl(Ptr<dentry> dentry, String acl_name,
      Ptr<posix_acl> kacl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_inode_post_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      int ia_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_post_setxattr($arg1, (const u8*)$arg2, (const void*)$arg3, $arg4, $arg5)")
  public static void bpf_lsm_inode_post_setxattr(Ptr<dentry> dentry, String name, Ptr<?> value,
      @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_readlink(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_remove_acl($arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_lsm_inode_remove_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String acl_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_removexattr($arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_lsm_inode_removexattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_rename(Ptr<inode> old_dir, Ptr<dentry> old_dentry,
      Ptr<inode> new_dir, Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_rmdir(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_set_acl($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static int bpf_lsm_inode_set_acl(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, String acl_name,
      Ptr<posix_acl> kacl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry,
      Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_setintegrity((const struct inode*)$arg1, $arg2, (const void*)$arg3, $arg4)")
  public static int bpf_lsm_inode_setintegrity(Ptr<inode> inode, lsm_integrity_type type,
      Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_setsecctx(Ptr<dentry> dentry, Ptr<?> ctx, @Unsigned int ctxlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_setsecurity($arg1, (const u8*)$arg2, (const void*)$arg3, $arg4, $arg5)")
  public static int bpf_lsm_inode_setsecurity(Ptr<inode> inode, String name, Ptr<?> value,
      @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_setxattr($arg1, $arg2, (const u8*)$arg3, (const void*)$arg4, $arg5, $arg6)")
  public static int bpf_lsm_inode_setxattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, String name,
      Ptr<?> value, @Unsigned long size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_symlink($arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_lsm_inode_symlink(Ptr<inode> dir, Ptr<dentry> dentry, String old_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_inode_unlink(Ptr<inode> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_inode_xattr_skipcap((const u8*)$arg1)")
  public static int bpf_lsm_inode_xattr_skipcap(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_ipc_getlsmprop(Ptr<kern_ipc_perm> ipcp, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_ipc_permission(Ptr<kern_ipc_perm> ipcp, short flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_lsm_is_sleepable_hook(@Unsigned int btf_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_is_trusted((const struct bpf_prog*)$arg1)")
  public static boolean bpf_lsm_is_trusted(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_ismaclabel((const u8*)$arg1)")
  public static int bpf_lsm_ismaclabel(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_act_as(Ptr<cred> _new, @Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_create_files_as(Ptr<cred> _new, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_load_data(kernel_load_data_id id, boolean contents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_module_request(String kmod_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_post_load_data(String buf, @OriginalName("loff_t") long size,
      kernel_load_data_id id, String description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_post_read_file(Ptr<file> file, String buf,
      @OriginalName("loff_t") long size, kernel_read_file_id id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernel_read_file(Ptr<file> file, kernel_read_file_id id,
      boolean contents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_kernfs_init_security(Ptr<kernfs_node> kn_dir, Ptr<kernfs_node> kn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_key_alloc($arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_key_alloc(Ptr<key> key, Ptr<cred> cred, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_key_getsecurity(Ptr<key> key, Ptr<String> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_key_permission($arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_key_permission(
      @OriginalName("__key_reference_with_attributes") @OriginalName("__key_reference_with_attributes") @OriginalName("key_ref_t") Ptr<?> key_ref,
      Ptr<cred> cred, key_need_perm need_perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_key_post_create_or_update($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6)")
  public static void bpf_lsm_key_post_create_or_update(Ptr<key> keyring, Ptr<key> key,
      Ptr<?> payload, @Unsigned long payload_len, @Unsigned long flags, boolean create) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_lock_kernel_down((const u8*)$arg1, $arg2)")
  public static int bpf_lsm_lock_kernel_down(String where, lockdown_reason level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_locked_down(lockdown_reason what) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_lsmprop_to_secctx(Ptr<lsm_prop> prop, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_mmap_addr(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_mmap_file(Ptr<file> file, @Unsigned long reqprot, @Unsigned long prot,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_move_mount((const struct path*)$arg1, (const struct path*)$arg2)")
  public static int bpf_lsm_move_mount(Ptr<path> from_path, Ptr<path> to_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_mptcp_add_subflow(Ptr<sock> sk, Ptr<sock> ssk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_msg_alloc_security(Ptr<msg_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_msg_msg_free_security(Ptr<msg_msg> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_queue_alloc_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_queue_associate(Ptr<kern_ipc_perm> perm, int msqflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_msg_queue_free_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_queue_msgctl(Ptr<kern_ipc_perm> perm, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_queue_msgrcv(Ptr<kern_ipc_perm> perm, Ptr<msg_msg> msg,
      Ptr<task_struct> target, long type, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_msg_queue_msgsnd(Ptr<kern_ipc_perm> perm, Ptr<msg_msg> msg,
      int msqflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_netlink_send(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_chmod((const struct path*)$arg1, $arg2)")
  public static int bpf_lsm_path_chmod(Ptr<path> path,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_chown((const struct path*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_path_chown(Ptr<path> path, kuid_t uid, kgid_t gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_chroot((const struct path*)$arg1)")
  public static int bpf_lsm_path_chroot(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_link($arg1, (const struct path*)$arg2, $arg3)")
  public static int bpf_lsm_path_link(Ptr<dentry> old_dentry, Ptr<path> new_dir,
      Ptr<dentry> new_dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_mkdir((const struct path*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_path_mkdir(Ptr<path> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_mknod((const struct path*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_lsm_path_mknod(Ptr<path> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned int dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_notify((const struct path*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_path_notify(Ptr<path> path, @Unsigned long mask,
      @Unsigned int obj_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_path_post_mknod(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_rename((const struct path*)$arg1, $arg2, (const struct path*)$arg3, $arg4, $arg5)")
  public static int bpf_lsm_path_rename(Ptr<path> old_dir, Ptr<dentry> old_dentry,
      Ptr<path> new_dir, Ptr<dentry> new_dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_rmdir((const struct path*)$arg1, $arg2)")
  public static int bpf_lsm_path_rmdir(Ptr<path> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_symlink((const struct path*)$arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_lsm_path_symlink(Ptr<path> dir, Ptr<dentry> dentry, String old_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_truncate((const struct path*)$arg1)")
  public static int bpf_lsm_path_truncate(Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_path_unlink((const struct path*)$arg1, $arg2)")
  public static int bpf_lsm_path_unlink(Ptr<path> dir, Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_perf_event_alloc(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_perf_event_open(int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_perf_event_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_perf_event_write(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_post_notification((const struct cred*)$arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_post_notification(Ptr<cred> w_cred, Ptr<cred> cred,
      Ptr<watch_notification> n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_ptrace_access_check(Ptr<task_struct> child, @Unsigned int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_ptrace_traceme(Ptr<task_struct> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_quota_on(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_quotactl($arg1, $arg2, $arg3, (const struct super_block*)$arg4)")
  public static int bpf_lsm_quotactl(int cmds, int type, int id, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_release_secctx(Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_req_classify_flow((const struct request_sock*)$arg1, $arg2)")
  public static void bpf_lsm_req_classify_flow(Ptr<request_sock> req, Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_alloc_security(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sb_clone_mnt_opts((const struct super_block*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_lsm_sb_clone_mnt_opts(Ptr<super_block> oldsb, Ptr<super_block> newsb,
      @Unsigned long kern_flags, Ptr<java.lang. @Unsigned Long> set_kern_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sb_delete(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_eat_lsm_opts(String orig, Ptr<Ptr<?>> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sb_free_mnt_opts(Ptr<?> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sb_free_security(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sb_kern_mount((const struct super_block*)$arg1)")
  public static int bpf_lsm_sb_kern_mount(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_mnt_opts_compat(Ptr<super_block> sb, Ptr<?> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sb_mount((const u8*)$arg1, (const struct path*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static int bpf_lsm_sb_mount(String dev_name, Ptr<path> path, String type,
      @Unsigned long flags, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sb_pivotroot((const struct path*)$arg1, (const struct path*)$arg2)")
  public static int bpf_lsm_sb_pivotroot(Ptr<path> old_path, Ptr<path> new_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_remount(Ptr<super_block> sb, Ptr<?> mnt_opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_set_mnt_opts(Ptr<super_block> sb, Ptr<?> mnt_opts,
      @Unsigned long kern_flags, Ptr<java.lang. @Unsigned Long> set_kern_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_show_options(Ptr<seq_file> m, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_statfs(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sb_umount(Ptr<vfsmount> mnt, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sctp_assoc_established(Ptr<sctp_association> asoc, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sctp_assoc_request(Ptr<sctp_association> asoc, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sctp_bind_connect(Ptr<sock> sk, int optname, Ptr<sockaddr> address,
      int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sctp_sk_clone(Ptr<sctp_association> asoc, Ptr<sock> sk,
      Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_secctx_to_secid((const u8*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_secctx_to_secid(String secdata, @Unsigned int seclen,
      Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_secid_to_secctx(@Unsigned int secid, Ptr<lsm_context> cp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_secmark_refcount_dec() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_secmark_refcount_inc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_secmark_relabel_packet(@Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sem_alloc_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sem_associate(Ptr<kern_ipc_perm> perm, int semflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sem_free_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sem_semctl(Ptr<kern_ipc_perm> perm, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sem_semop(Ptr<kern_ipc_perm> perm, Ptr<sembuf> sops,
      @Unsigned int nsops, int alter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_setprocattr((const u8*)$arg1, $arg2, $arg3)")
  public static int bpf_lsm_setprocattr(String name, Ptr<?> value, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_setselfattr(@Unsigned int attr, Ptr<lsm_ctx> ctx, @Unsigned int size,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_settime((const struct timespec64*)$arg1, (const struct timezone*)$arg2)")
  public static int bpf_lsm_settime(Ptr<timespec64> ts, Ptr<timezone> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_shm_alloc_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_shm_associate(Ptr<kern_ipc_perm> perm, int shmflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_shm_free_security(Ptr<kern_ipc_perm> perm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_shm_shmat(Ptr<kern_ipc_perm> perm, String shmaddr, int shmflg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_shm_shmctl(Ptr<kern_ipc_perm> perm, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_sk_alloc_security(Ptr<sock> sk, int family,
      @Unsigned @OriginalName("gfp_t") int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sk_clone_security((const struct sock*)$arg1, $arg2)")
  public static void bpf_lsm_sk_clone_security(Ptr<sock> sk, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sk_free_security(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_sk_getsecid((const struct sock*)$arg1, $arg2)")
  public static void bpf_lsm_sk_getsecid(Ptr<sock> sk, Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_sock_graft(Ptr<sock> sk, Ptr<socket> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_accept(Ptr<socket> sock, Ptr<socket> newsock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_bind(Ptr<socket> sock, Ptr<sockaddr> address, int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_connect(Ptr<socket> sock, Ptr<sockaddr> address, int addrlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_create(int family, int type, int protocol, int kern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_getpeername(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_getpeersec_dgram(Ptr<socket> sock, Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_getpeersec_stream(Ptr<socket> sock, sockptr_t optval,
      sockptr_t optlen, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_getsockname(Ptr<socket> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_getsockopt(Ptr<socket> sock, int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_listen(Ptr<socket> sock, int backlog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_post_create(Ptr<socket> sock, int family, int type, int protocol,
      int kern) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_recvmsg(Ptr<socket> sock, Ptr<msghdr> msg, int size, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_sendmsg(Ptr<socket> sock, Ptr<msghdr> msg, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_setsockopt(Ptr<socket> sock, int level, int optname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_shutdown(Ptr<socket> sock, int how) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_sock_rcv_skb(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_socket_socketpair(Ptr<socket> socka, Ptr<socket> sockb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_syslog(int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_alloc(Ptr<task_struct> task, @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_task_fix_setgid($arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_task_fix_setgid(Ptr<cred> _new, Ptr<cred> old, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_task_fix_setgroups($arg1, (const struct cred*)$arg2)")
  public static int bpf_lsm_task_fix_setgroups(Ptr<cred> _new, Ptr<cred> old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_task_fix_setuid($arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_task_fix_setuid(Ptr<cred> _new, Ptr<cred> old, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_task_free(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_getioprio(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_task_getlsmprop_obj(Ptr<task_struct> p, Ptr<lsm_prop> prop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_getpgid(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_getscheduler(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_getsid(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_task_kill($arg1, $arg2, $arg3, (const struct cred*)$arg4)")
  public static int bpf_lsm_task_kill(Ptr<task_struct> p, Ptr<kernel_siginfo> info, int sig,
      Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_movememory(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_prctl(int option, @Unsigned long arg2, @Unsigned long arg3,
      @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_task_prlimit((const struct cred*)$arg1, (const struct cred*)$arg2, $arg3)")
  public static int bpf_lsm_task_prlimit(Ptr<cred> cred, Ptr<cred> tcred, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_setioprio(Ptr<task_struct> p, int ioprio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_setnice(Ptr<task_struct> p, int nice) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_setpgid(Ptr<task_struct> p, @OriginalName("pid_t") int pgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_setrlimit(Ptr<task_struct> p, @Unsigned int resource,
      Ptr<rlimit> new_rlim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_task_setscheduler(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_task_to_inode(Ptr<task_struct> p, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_tun_dev_alloc_security(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_tun_dev_attach(Ptr<sock> sk, Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_tun_dev_attach_queue(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_tun_dev_create() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_tun_dev_open(Ptr<?> security) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_unix_may_send(Ptr<socket> sock, Ptr<socket> other) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_unix_stream_connect(Ptr<sock> sock, Ptr<sock> other, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_uring_allowed() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_uring_cmd(Ptr<io_uring_cmd> ioucmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_uring_override_creds((const struct cred*)$arg1)")
  public static int bpf_lsm_uring_override_creds(Ptr<cred> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_uring_sqpoll() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_userns_create((const struct cred*)$arg1)")
  public static int bpf_lsm_userns_create(Ptr<cred> cred) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_verify_prog($arg1, (const struct bpf_prog*)$arg2)")
  public static int bpf_lsm_verify_prog(Ptr<bpf_verifier_log> vlog, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_vm_enough_memory(Ptr<mm_struct> mm, long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_watch_key(Ptr<key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_decode_session(Ptr<sk_buff> skb,
      Ptr<java.lang. @Unsigned Integer> secid, int ckall) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_policy_alloc_security(Ptr<Ptr<xfrm_sec_ctx>> ctxp,
      Ptr<xfrm_user_sec_ctx> sec_ctx, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_policy_clone_security(Ptr<xfrm_sec_ctx> old_ctx,
      Ptr<Ptr<xfrm_sec_ctx>> new_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_policy_delete_security(Ptr<xfrm_sec_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_xfrm_policy_free_security(Ptr<xfrm_sec_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_policy_lookup(Ptr<xfrm_sec_ctx> ctx, @Unsigned int fl_secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_state_alloc(Ptr<xfrm_state> x, Ptr<xfrm_user_sec_ctx> sec_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_state_alloc_acquire(Ptr<xfrm_state> x, Ptr<xfrm_sec_ctx> polsec,
      @Unsigned int secid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lsm_xfrm_state_delete_security(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_lsm_xfrm_state_free_security(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_lsm_xfrm_state_pol_flow_match($arg1, $arg2, (const struct flowi_common*)$arg3)")
  public static int bpf_lsm_xfrm_state_pol_flow_match(Ptr<xfrm_state> x, Ptr<xfrm_policy> xp,
      Ptr<flowi_common> flic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_lwt_in_push_encap(@Unsigned long skb, @Unsigned long type,
      @Unsigned long hdr, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lwt_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lwt_input_reroute(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lwt_push_ip_encap(Ptr<sk_buff> skb, Ptr<?> hdr, @Unsigned int len,
      boolean ingress) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_lwt_seg6_action(@Unsigned long skb, @Unsigned long action,
      @Unsigned long param, @Unsigned long param_len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_lwt_seg6_adjust_srh(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_lwt_seg6_store_bytes(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long from, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_lwt_xmit_push_encap(@Unsigned long skb, @Unsigned long type,
      @Unsigned long hdr, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_lwt_xmit_reroute(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_alloc_pages((const struct bpf_map*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_map_alloc_pages(Ptr<bpf_map> map, int nid, @Unsigned long nr_pages,
      Ptr<Ptr<page>> pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_alloc_percpu((const struct bpf_map*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<?> bpf_map_alloc_percpu(Ptr<bpf_map> map, @Unsigned long size,
      @Unsigned long align, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_area_alloc(@Unsigned long size, int numa_node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_area_free(Ptr<?> area) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_area_mmapable_alloc(@Unsigned long size, int numa_node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_copy_value(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_delete_elem(@Unsigned long map, @Unsigned long key,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_do_batch((const union bpf_attr*)$arg1, $arg2, $arg3)")
  public static int bpf_map_do_batch(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr, int cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_fd_get_ptr(Ptr<bpf_map> map, Ptr<file> map_file, int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_fd_put_ptr(Ptr<bpf_map> map, Ptr<?> ptr, boolean need_defer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_map_fd_sys_lookup_elem(Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_free_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_free_id(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_free_mult_rcu_gp(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_free_rcu_gp(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_free_record(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_get(@Unsigned int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_get_curr_or_next(Ptr<java.lang. @Unsigned Integer> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_get_fd_by_id((const union bpf_attr*)$arg1)")
  public static int bpf_map_get_fd_by_id(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_get_memcg((const struct bpf_map*)$arg1)")
  public static Ptr<mem_cgroup> bpf_map_get_memcg(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_get_with_uref(@Unsigned int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_inc(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_inc_not_zero(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_inc_with_uref(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_init_from_attr(Ptr<bpf_map> map, Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_kmalloc_node((const struct bpf_map*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<?> bpf_map_kmalloc_node(Ptr<bpf_map> map, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_kvcalloc(Ptr<bpf_map> map, @Unsigned long n, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_kzalloc((const struct bpf_map*)$arg1, $arg2, $arg3)")
  public static Ptr<?> bpf_map_kzalloc(Ptr<bpf_map> map, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_lookup_elem(@Unsigned long map, @Unsigned long key,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_lookup_percpu_elem(@Unsigned long map, @Unsigned long key,
      @Unsigned long cpu, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_meta_alloc(int inner_map_ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_meta_equal((const struct bpf_map*)$arg1, (const struct bpf_map*)$arg2)")
  public static boolean bpf_map_meta_equal(Ptr<bpf_map> meta0, Ptr<bpf_map> meta1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_meta_free(Ptr<bpf_map> map_meta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_mmap(Ptr<file> filp, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_mmap_close(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_mmap_open(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_new_fd(Ptr<bpf_map> map, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_get_next_key(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> next_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_info_fill(Ptr<bpf_map_info> info, Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ns_common> bpf_map_offload_info_fill_ns(Ptr<?> private_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_lookup_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_map_offload_map_alloc(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_offload_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_offload_map_mem_usage((const struct bpf_map*)$arg1)")
  public static @Unsigned long bpf_map_offload_map_mem_usage(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_ndo(Ptr<bpf_offloaded_map> offmap, bpf_netdev_command cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_offload_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_peek_elem(@Unsigned long map, @Unsigned long value,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int bpf_map_poll(Ptr<file> filp,
      Ptr<poll_table_struct> pts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_pop_elem(@Unsigned long map, @Unsigned long value,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_push_elem(@Unsigned long map, @Unsigned long value,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_put(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_put_with_uref(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_map_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_show_fdinfo(Ptr<seq_file> m, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_map_struct_ops_info_fill(Ptr<bpf_map_info> info, Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_sum_elem_count((const struct bpf_map*)$arg1)")
  public static long bpf_map_sum_elem_count(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_map_update_elem(@Unsigned long map, @Unsigned long key,
      @Unsigned long value, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_map_update_value(Ptr<bpf_map> map, Ptr<file> map_file, Ptr<?> key,
      Ptr<?> value, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_value_size((const struct bpf_map*)$arg1)")
  public static @Unsigned int bpf_map_value_size(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_map_write_active((const struct bpf_map*)$arg1)")
  public static boolean bpf_map_write_active(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mem_alloc_check_size(boolean percpu, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_alloc_destroy(Ptr<bpf_mem_alloc> ma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mem_alloc_init(Ptr<bpf_mem_alloc> ma, int size, boolean percpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mem_alloc_percpu_init(Ptr<bpf_mem_alloc> ma, Ptr<obj_cgroup> objcg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mem_alloc_percpu_unit_init(Ptr<bpf_mem_alloc> ma, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_mem_cache_alloc(Ptr<bpf_mem_alloc> ma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_mem_cache_alloc_flags(Ptr<bpf_mem_alloc> ma,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_cache_free(Ptr<bpf_mem_alloc> ma, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_cache_free_rcu(Ptr<bpf_mem_alloc> ma, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_cache_raw_free(Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_free(Ptr<bpf_mem_alloc> ma, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_free_rcu(Ptr<bpf_mem_alloc> ma, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mem_refill(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> bpf_mkdir(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mklink(Ptr<dentry> dentry, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mkmap(Ptr<dentry> dentry, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_mkobj_ops($arg1, $arg2, $arg3, (const struct inode_operations*)$arg4, (const struct file_operations*)$arg5)")
  public static int bpf_mkobj_ops(Ptr<dentry> dentry, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<?> raw, Ptr<inode_operations> iops, Ptr<file_operations> fops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mkprog(Ptr<dentry> dentry, @Unsigned @OriginalName("umode_t") short mode,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_modify_return_test(int a, Ptr<java.lang.Integer> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_modify_return_test2(int a, Ptr<java.lang.Integer> b, short c, int d,
      Ptr<?> e, char f, int g) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_modify_return_test_tp(int nonce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mprog_attach(Ptr<bpf_mprog_entry> entry,
      Ptr<Ptr<bpf_mprog_entry>> entry_new, Ptr<bpf_prog> prog_new, Ptr<bpf_link> link,
      Ptr<bpf_prog> prog_old, @Unsigned int flags, @Unsigned int id_or_fd,
      @Unsigned long revision) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mprog_detach(Ptr<bpf_mprog_entry> entry,
      Ptr<Ptr<bpf_mprog_entry>> entry_new, Ptr<bpf_prog> prog, Ptr<bpf_link> link,
      @Unsigned int flags, @Unsigned int id_or_fd, @Unsigned long revision) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mprog_entry_copy(Ptr<bpf_mprog_entry> dst, Ptr<bpf_mprog_entry> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mprog_entry_grow(Ptr<bpf_mprog_entry> entry, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_mprog_entry_shrink(Ptr<bpf_mprog_entry> entry, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mprog_pos_after(Ptr<bpf_mprog_entry> entry, Ptr<bpf_tuple> tuple) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mprog_pos_before(Ptr<bpf_mprog_entry> entry, Ptr<bpf_tuple> tuple) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_mprog_query((const union bpf_attr*)$arg1, $arg2, $arg3)")
  public static int bpf_mprog_query(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr,
      Ptr<bpf_mprog_entry> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mprog_tuple_relative(Ptr<bpf_tuple> tuple, @Unsigned int id_or_fd,
      @Unsigned int flags, bpf_prog_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_mptcp_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mptcp_sock> bpf_mptcp_sock_from_subflow(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_apply_bytes(@Unsigned long msg, @Unsigned long bytes,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_cork_bytes(@Unsigned long msg, @Unsigned long bytes,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_pop_data(@Unsigned long msg, @Unsigned long start,
      @Unsigned long len, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_pull_data(@Unsigned long msg, @Unsigned long start,
      @Unsigned long end, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_push_data(@Unsigned long msg, @Unsigned long start,
      @Unsigned long len, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_redirect_hash(@Unsigned long msg, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_msg_redirect_map(@Unsigned long msg, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_netns_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_netns_link_detach(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_netns_link_fill_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_netns_link_fill_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_netns_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_netns_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_netns_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_netns_link_update_prog(Ptr<bpf_link> link, Ptr<bpf_prog> new_prog,
      Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_nf_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_nf_func_proto(bpf_func_id func_id, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_nf_link_attach((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_nf_link_attach(Ptr<bpf_attr> attr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_nf_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_nf_link_detach(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_nf_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_nf_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_nf_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_nf_link_show_info((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_nf_link_show_info(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_nf_link_update(Ptr<bpf_link> link, Ptr<bpf_prog> new_prog,
      Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_noop_prologue($arg1, $arg2, (const struct bpf_prog*)$arg3)")
  public static int bpf_noop_prologue(Ptr<bpf_insn> insn_buf, boolean direct_write,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_obj_drop_impl(Ptr<?> p__alloc, Ptr<?> meta__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_free_fields((const struct btf_record*)$arg1, $arg2)")
  public static void bpf_obj_free_fields(Ptr<btf_record> rec, Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_free_timer((const struct btf_record*)$arg1, $arg2)")
  public static void bpf_obj_free_timer(Ptr<btf_record> rec, Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_free_workqueue((const struct btf_record*)$arg1, $arg2)")
  public static void bpf_obj_free_workqueue(Ptr<btf_record> rec, Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_get_info_by_fd((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_obj_get_info_by_fd(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_get_next_id((const union bpf_attr*)$arg1, $arg2, $arg3, $arg4)")
  public static int bpf_obj_get_next_id(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr, Ptr<idr> idr,
      Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_get_user($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_obj_get_user(int path_fd, String pathname, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_init((const struct btf_record*)$arg1, $arg2)")
  public static void bpf_obj_init(Ptr<btf_record> rec, Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_obj_memcpy(Ptr<btf_record> rec, Ptr<?> dst, Ptr<?> src, @Unsigned int size,
      boolean long_memcpy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_name_cpy($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_obj_name_cpy(String dst, String src, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_obj_new_impl(@Unsigned long local_type_id__k, Ptr<?> meta__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_obj_pin_uptrs(Ptr<btf_record> rec, Ptr<?> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_obj_pin_user($arg1, $arg2, (const u8*)$arg3)")
  public static int bpf_obj_pin_user(@Unsigned int ufd, int path_fd, String pathname) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_offload_dev_create((const struct bpf_prog_offload_ops*)$arg1, $arg2)")
  public static Ptr<bpf_offload_dev> bpf_offload_dev_create(Ptr<bpf_prog_offload_ops> ops,
      Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_offload_dev_destroy(Ptr<bpf_offload_dev> offdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_offload_dev_match(Ptr<bpf_prog> prog, Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_offload_dev_netdev_register(Ptr<bpf_offload_dev> offdev,
      Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_offload_dev_netdev_unregister(Ptr<bpf_offload_dev> offdev,
      Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_offload_dev_priv(Ptr<bpf_offload_dev> offdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_offload_netdev> bpf_offload_find_netdev(Ptr<net_device> netdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_offload_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_offload_prog_map_match(Ptr<bpf_prog> prog, Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_opcode_in_insntable(char code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_out_neigh_v6(Ptr<net> net, Ptr<sk_buff> skb, Ptr<net_device> dev,
      Ptr<bpf_nh_params> nh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_output(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_override_return(@Unsigned long regs, @Unsigned long rc,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_parse_param(Ptr<fs_context> fc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_parse_prog(Ptr<nlattr> attr, Ptr<bpf_lwt_prog> prog, bpf_prog_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_patch_insn_data($arg1, $arg2, (const struct bpf_insn*)$arg3, $arg4)")
  public static Ptr<bpf_prog> bpf_patch_insn_data(Ptr<bpf_verifier_env> env, @Unsigned int off,
      Ptr<bpf_insn> patch, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_patch_insn_single($arg1, $arg2, (const struct bpf_insn*)$arg3, $arg4)")
  public static Ptr<bpf_prog> bpf_patch_insn_single(Ptr<bpf_prog> prog, @Unsigned int off,
      Ptr<bpf_insn> patch, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_path_d_path(Ptr<path> path, String buf, @Unsigned long buf__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_per_cpu_ptr(@Unsigned long ptr, @Unsigned long cpu,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_array_copy(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_array_update(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_cgroup_storage_copy(Ptr<bpf_map> _map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_cgroup_storage_update(Ptr<bpf_map> _map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_hash_copy(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_percpu_hash_update(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_percpu_lru_populate(Ptr<bpf_lru> lru, Ptr<?> buf,
      @Unsigned int node_offset, @Unsigned int elem_size, @Unsigned int nr_elems) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_percpu_obj_drop_impl(Ptr<?> p__alloc, Ptr<?> meta__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_percpu_obj_new_impl(@Unsigned long local_type_id__k, Ptr<?> meta__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_output(@Unsigned long regs, @Unsigned long map,
      @Unsigned long flags, @Unsigned long data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_output_raw_tp(@Unsigned long args, @Unsigned long map,
      @Unsigned long flags, @Unsigned long data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_output_tp(@Unsigned long tp_buff, @Unsigned long map,
      @Unsigned long flags, @Unsigned long data, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_read(@Unsigned long map, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_event_read_value(@Unsigned long map, @Unsigned long flags,
      @Unsigned long buf, @Unsigned long size, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_perf_link_attach((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_perf_link_attach(Ptr<bpf_attr> attr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_perf_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_perf_link_fill_common((const struct perf_event*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int bpf_perf_link_fill_common(Ptr<perf_event> event, String uname,
      Ptr<java.lang. @Unsigned Integer> ulenp, Ptr<java.lang. @Unsigned Long> probe_offset,
      Ptr<java.lang. @Unsigned Long> probe_addr, Ptr<java.lang. @Unsigned Integer> fd_type,
      Ptr<java.lang. @Unsigned Long> missed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_perf_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_perf_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_perf_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_perf_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_perf_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_perf_prog_read_value(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_pid_task_storage_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_pid_task_storage_lookup_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_pid_task_storage_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long map_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_preempt_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_preempt_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prepare_filter(Ptr<bpf_prog> fp,
      @OriginalName("bpf_aux_classic_check_t") Ptr<?> trans) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_compat(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_compat_str(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_kernel(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_kernel_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_probe_read_kernel_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_kernel_str(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_kernel_str_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_probe_read_kernel_str_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_user(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_user_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_probe_read_user_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_read_user_str(@Unsigned long dst, @Unsigned long size,
      @Unsigned long unsafe_ptr, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_probe_read_user_str_dynptr($arg1, $arg2, $arg3, (const void*)$arg4)")
  public static int bpf_probe_read_user_str_dynptr(Ptr<bpf_dynptr> dptr, @Unsigned int off,
      @Unsigned int size, Ptr<?> unsafe_ptr__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_probe_register(Ptr<bpf_raw_event_map> btp, Ptr<bpf_raw_tp_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_probe_unregister(Ptr<bpf_raw_event_map> btp, Ptr<bpf_raw_tp_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_probe_write_user(@Unsigned long unsafe_ptr, @Unsigned long src,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_add(Ptr<bpf_prog> prog, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_alloc(@Unsigned int size,
      @Unsigned @OriginalName("gfp_t") int gfp_extra_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_alloc_jited_linfo(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_alloc_no_stats(@Unsigned int size,
      @Unsigned @OriginalName("gfp_t") int gfp_extra_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog_array> bpf_prog_array_alloc(@Unsigned int prog_cnt,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_copy(Ptr<bpf_prog_array> old_array, Ptr<bpf_prog> exclude_prog,
      Ptr<bpf_prog> include_prog, @Unsigned long bpf_cookie, Ptr<Ptr<bpf_prog_array>> new_array) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_copy_info(Ptr<bpf_prog_array> array,
      Ptr<java.lang. @Unsigned Integer> prog_ids, @Unsigned int request_cnt,
      Ptr<java.lang. @Unsigned Integer> prog_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_copy_to_user(Ptr<bpf_prog_array> array,
      Ptr<java.lang. @Unsigned Integer> prog_ids, @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_array_delete_safe(Ptr<bpf_prog_array> array, Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_delete_safe_at(Ptr<bpf_prog_array> array, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_array_free(Ptr<bpf_prog_array> progs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_array_free_sleepable(Ptr<bpf_prog_array> progs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_prog_array_is_empty(Ptr<bpf_prog_array> array) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_length(Ptr<bpf_prog_array> array) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_array_update_at(Ptr<bpf_prog_array> array, int index,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_attach((const union bpf_attr*)$arg1)")
  public static int bpf_prog_attach(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_attach_check_attach_type((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_prog_attach_check_attach_type(Ptr<bpf_prog> prog,
      bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_bind_map(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_by_id(@Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_calc_tag(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_change_xdp(Ptr<bpf_prog> prev_prog, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_clone_create(Ptr<bpf_prog> fp_other,
      @Unsigned @OriginalName("gfp_t") int gfp_extra_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_create(Ptr<Ptr<bpf_prog>> pfp, Ptr<sock_fprog_kern> fprog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_create_from_user(Ptr<Ptr<bpf_prog>> pfp, Ptr<sock_fprog> fprog,
      @OriginalName("bpf_aux_classic_check_t") Ptr<?> trans, boolean save_orig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_ctx_arg_info_init($arg1, (const struct bpf_ctx_arg_aux*)$arg2, $arg3)")
  public static int bpf_prog_ctx_arg_info_init(Ptr<bpf_prog> prog, Ptr<bpf_ctx_arg_aux> info,
      @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_destroy(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_detach((const union bpf_attr*)$arg1)")
  public static int bpf_prog_detach(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_dev_bound_destroy(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_dev_bound_inherit(Ptr<bpf_prog> new_prog, Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_dev_bound_init(Ptr<bpf_prog> prog, Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_dev_bound_match((const struct bpf_prog*)$arg1, (const struct bpf_prog*)$arg2)")
  public static boolean bpf_prog_dev_bound_match(Ptr<bpf_prog> lhs, Ptr<bpf_prog> rhs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_fill_jited_linfo($arg1, (const unsigned int*)$arg2)")
  public static void bpf_prog_fill_jited_linfo(Ptr<bpf_prog> prog,
      Ptr<java.lang. @Unsigned Integer> insn_to_jit_off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_find_from_stack() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_free(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_free_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_free_id(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_get(@Unsigned int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_get_curr_or_next(Ptr<java.lang. @Unsigned Integer> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_get_file_line($arg1, $arg2, (const u8**)$arg3, (const u8**)$arg4, $arg5)")
  public static int bpf_prog_get_file_line(Ptr<bpf_prog> prog, @Unsigned long ip, Ptr<String> filep,
      Ptr<String> linep, Ptr<java.lang.Integer> nump) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_get_info_by_fd($arg1, $arg2, (const union bpf_attr*)$arg3, $arg4)")
  public static int bpf_prog_get_info_by_fd(Ptr<file> file, Ptr<bpf_prog> prog, Ptr<bpf_attr> attr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_prog_get_ok(Ptr<bpf_prog> prog, Ptr<bpf_prog_type> attach_type,
      boolean attach_drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_get_stats((const struct bpf_prog*)$arg1, $arg2)")
  public static void bpf_prog_get_stats(Ptr<bpf_prog> prog, Ptr<bpf_prog_kstats> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_get_target_btf((const struct bpf_prog*)$arg1)")
  public static Ptr<btf> bpf_prog_get_target_btf(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_get_type_dev(@Unsigned int ufd, bpf_prog_type type,
      boolean attach_drv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_get_type_path((const u8*)$arg1, $arg2)")
  public static Ptr<bpf_prog> bpf_prog_get_type_path(String name, bpf_prog_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_has_kfunc_call((const struct bpf_prog*)$arg1)")
  public static boolean bpf_prog_has_kfunc_call(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_has_trampoline((const struct bpf_prog*)$arg1)")
  public static boolean bpf_prog_has_trampoline(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_inc(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_inc_misses_counter(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_inc_not_zero(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_jit_attempt_done(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_kallsyms_add(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_kallsyms_del(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_kallsyms_del_all(Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_ksym_find(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_load(Ptr<bpf_attr> attr, @OriginalName("bpfptr_t") sockptr_t uattr,
      @Unsigned int uattr_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_load_check_attach(bpf_prog_type prog_type,
      bpf_attach_type expected_attach_type, Ptr<btf> attach_btf, @Unsigned int btf_id,
      Ptr<bpf_prog> dst_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_map_compatible($arg1, (const struct bpf_prog*)$arg2)")
  public static boolean bpf_prog_map_compatible(Ptr<bpf_map> map, Ptr<bpf_prog> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_new_fd(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_offload_compile(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_offload_finalize(Ptr<bpf_verifier_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_offload_info_fill(Ptr<bpf_prog_info> info, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ns_common> bpf_prog_offload_info_fill_ns(Ptr<?> private_data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_offload_remove_insns(Ptr<bpf_verifier_env> env, @Unsigned int off,
      @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_offload_replace_insn(Ptr<bpf_verifier_env> env, @Unsigned int off,
      Ptr<bpf_insn> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_offload_verifier_prep(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_offload_verify_insn(Ptr<bpf_verifier_env> env, int insn_idx,
      int prev_insn_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_prog_pack_alloc(@Unsigned int size,
      @OriginalName("bpf_jit_fill_hole_t") Ptr<?> bpf_fill_ill_insns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_pack_free(Ptr<?> ptr, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_put(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_put_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_query((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_prog_query(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_realloc(Ptr<bpf_prog> fp_old, @Unsigned int size,
      @Unsigned @OriginalName("gfp_t") int gfp_extra_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_report_may_goto_violation() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_report_rqspinlock_violation((const u8*)$arg1, $arg2, $arg3)")
  public static void bpf_prog_report_rqspinlock_violation(String str, Ptr<?> lock,
      boolean irqsave) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_run_generic_xdp($arg1, $arg2, (const struct bpf_prog*)$arg3)")
  public static @Unsigned int bpf_prog_run_generic_xdp(Ptr<sk_buff> skb, Ptr<xdp_buff> xdp,
      Ptr<bpf_prog> xdp_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_prog> bpf_prog_select_runtime(Ptr<bpf_prog> fp,
      Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_prog_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_prog_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_show_fdinfo(Ptr<seq_file> m, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_store_orig_filter($arg1, (const struct sock_fprog*)$arg2)")
  public static int bpf_prog_store_orig_filter(Ptr<bpf_prog> fp, Ptr<sock_fprog> fprog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_stream_free(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_stream_init(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_stream_read(Ptr<bpf_prog> prog, bpf_stream_id stream_id, Ptr<?> buf,
      int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_prog_sub(Ptr<bpf_prog> prog, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_flow_dissector($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_flow_dissector(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_prog_test_run_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_nf($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_nf(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_raw_tp($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_raw_tp(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_sk_lookup($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_sk_lookup(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_skb($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_skb(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_syscall($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_syscall(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_tracing($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_tracing(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_test_run_xdp($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_prog_test_run_xdp(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_prog_warn_on_exec((const void*)$arg1, (const struct bpf_insn*)$arg2)")
  public static @Unsigned int bpf_prog_warn_on_exec(Ptr<?> ctx, Ptr<bpf_insn> insn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_push_seg6_encap(Ptr<sk_buff> skb, @Unsigned int type, Ptr<?> hdr,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_put_buffers() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_put_file(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_put_raw_tracepoint(Ptr<bpf_raw_event_map> btp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_bstats_update($arg1, (const struct sk_buff*)$arg2)")
  public static void bpf_qdisc_bstats_update(Ptr<Qdisc> sch, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_btf_struct_access($arg1, (const struct bpf_reg_state*)$arg2, $arg3, $arg4)")
  public static int bpf_qdisc_btf_struct_access(Ptr<bpf_verifier_log> log, Ptr<bpf_reg_state> reg,
      int off, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_gen_epilogue($arg1, (const struct bpf_prog*)$arg2, $arg3)")
  public static int bpf_qdisc_gen_epilogue(Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog,
      short ctx_stack_off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_gen_prologue($arg1, $arg2, (const struct bpf_prog*)$arg3)")
  public static int bpf_qdisc_gen_prologue(Ptr<bpf_insn> insn_buf, boolean direct_write,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_qdisc_init(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_init_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, $arg3, (const void*)$arg4)")
  public static int bpf_qdisc_init_member(Ptr<btf_type> t, Ptr<btf_member> member, Ptr<?> kdata,
      Ptr<?> udata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_qdisc_init_prologue(Ptr<Qdisc> sch, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_is_valid_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean bpf_qdisc_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_prog> prog, Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_qdisc_kfunc_filter((const struct bpf_prog*)$arg1, $arg2)")
  public static int bpf_qdisc_kfunc_filter(Ptr<bpf_prog> prog, @Unsigned int kfunc_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_qdisc_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_qdisc_reg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_qdisc_reset_destroy_epilogue(Ptr<Qdisc> sch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_qdisc_skb_drop(Ptr<sk_buff> skb, Ptr<bpf_sk_buff_ptr> to_free_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_qdisc_unreg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_qdisc_validate(Ptr<?> kdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_qdisc_watchdog_schedule(Ptr<Qdisc> sch, @Unsigned long expire,
      @Unsigned long delta_ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_raw_tp_link_attach($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static int bpf_raw_tp_link_attach(Ptr<bpf_prog> prog, String user_tp_name,
      @Unsigned long cookie, bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_raw_tp_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_raw_tp_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_raw_tp_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_raw_tp_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_raw_tp_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_raw_tp_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_rb_root_free((const struct btf_field*)$arg1, $arg2, $arg3)")
  public static void bpf_rb_root_free(Ptr<btf_field> field, Ptr<?> rb_root,
      Ptr<bpf_spin_lock> spin_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_rbtree_add_impl($arg1, $arg2, (_Bool (*)(struct bpf_rb_node*, const struct bpf_rb_node*))$arg3, $arg4, $arg5)")
  public static int bpf_rbtree_add_impl(Ptr<bpf_rb_root> root, Ptr<bpf_rb_node> node, Ptr<?> less,
      Ptr<?> meta__ign, @Unsigned long off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_rb_node> bpf_rbtree_first(Ptr<bpf_rb_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_rb_node> bpf_rbtree_left(Ptr<bpf_rb_root> root, Ptr<bpf_rb_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_rb_node> bpf_rbtree_remove(Ptr<bpf_rb_root> root, Ptr<bpf_rb_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_rb_node> bpf_rbtree_right(Ptr<bpf_rb_root> root, Ptr<bpf_rb_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_rb_node> bpf_rbtree_root(Ptr<bpf_rb_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_rcu_read_lock() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_rcu_read_unlock() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_rdonly_cast((const void*)$arg1, $arg2)")
  public static Ptr<?> bpf_rdonly_cast(Ptr<?> obj__ign, @Unsigned int btf_id__k) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_read_branch_records(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_redirect(@Unsigned long ifindex, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_redirect_neigh(@Unsigned long ifindex, @Unsigned long params,
      @Unsigned long plen, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_redirect_peer(@Unsigned long ifindex, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_refcount_acquire_impl(Ptr<?> p__refcounted_kptr, Ptr<?> meta__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_remove_dentry_xattr($arg1, (const u8*)$arg2)")
  public static int bpf_remove_dentry_xattr(Ptr<dentry> dentry, String name__str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_remove_dentry_xattr_locked($arg1, (const u8*)$arg2)")
  public static int bpf_remove_dentry_xattr_locked(Ptr<dentry> dentry, String name__str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_remove_insns(Ptr<bpf_prog> prog, @Unsigned int off, @Unsigned int cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_res_spin_lock_irqsave(Ptr<bpf_res_spin_lock> lock,
      Ptr<java.lang. @Unsigned Long> flags__irq_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_res_spin_unlock(Ptr<bpf_res_spin_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_res_spin_unlock_irqrestore(Ptr<bpf_res_spin_lock> lock,
      Ptr<java.lang. @Unsigned Long> flags__irq_flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_commit(Ptr<?> sample, @Unsigned long flags, boolean discard) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_discard(@Unsigned long sample, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_discard_dynptr(@Unsigned long ptr, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_ringbuf_notify(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_output(@Unsigned long map, @Unsigned long data,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_query(@Unsigned long map, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_reserve(@Unsigned long map, @Unsigned long size,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_reserve_dynptr(@Unsigned long map, @Unsigned long size,
      @Unsigned long flags, @Unsigned long ptr, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_submit(@Unsigned long sample, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_ringbuf_submit_dynptr(@Unsigned long ptr, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_rstat_flush(Ptr<cgroup> cgrp, Ptr<cgroup> parent, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_rstat_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sock> bpf_run_sk_reuseport(Ptr<sock_reuseport> reuse, Ptr<sock> sk,
      Ptr<bpf_prog> prog, Ptr<sk_buff> skb, Ptr<sock> migrating_sk, @Unsigned int hash) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_scx_btf_struct_access($arg1, (const struct bpf_reg_state*)$arg2, $arg3, $arg4)")
  public static int bpf_scx_btf_struct_access(Ptr<bpf_verifier_log> log, Ptr<bpf_reg_state> reg,
      int off, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_scx_check_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, (const struct bpf_prog*)$arg3)")
  public static int bpf_scx_check_member(Ptr<btf_type> t, Ptr<btf_member> member,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_scx_init(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_scx_init_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, $arg3, (const void*)$arg4)")
  public static int bpf_scx_init_member(Ptr<btf_type> t, Ptr<btf_member> member, Ptr<?> kdata,
      Ptr<?> udata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_scx_is_valid_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean bpf_scx_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_prog> prog, Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_scx_reg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_scx_unreg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_scx_update(Ptr<?> kdata, Ptr<?> old_kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_scx_validate(Ptr<?> kdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)bpf_search_tcp_opt((const u8*)$arg1, (const u8*)$arg2, $arg3, (const u8*)$arg4, $arg5, $arg6))")
  public static Ptr<java.lang.Character> bpf_search_tcp_opt(Ptr<java.lang.Character> op,
      Ptr<java.lang.Character> opend, char search_kind, Ptr<java.lang.Character> magic,
      char magic_len, Ptr<java.lang. @OriginalName("bool") Boolean> eol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_local_storage_elem> bpf_selem_alloc(Ptr<bpf_local_storage_map> smap,
      Ptr<?> owner, Ptr<?> value, boolean charge_mem, boolean swap_uptrs,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_free(Ptr<bpf_local_storage_elem> selem,
      Ptr<bpf_local_storage_map> smap, boolean reuse_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_free_trace_rcu(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_link_map(Ptr<bpf_local_storage_map> smap,
      Ptr<bpf_local_storage_elem> selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_link_storage_nolock(Ptr<bpf_local_storage> local_storage,
      Ptr<bpf_local_storage_elem> selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_unlink(Ptr<bpf_local_storage_elem> selem, boolean reuse_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_unlink_map(Ptr<bpf_local_storage_elem> selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_selem_unlink_storage(Ptr<bpf_local_storage_elem> selem,
      boolean reuse_now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_send_signal(@Unsigned long sig, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_send_signal_common(@Unsigned int sig, pid_type type, Ptr<task_struct> task,
      @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_send_signal_task(Ptr<task_struct> task, int sig, pid_type type,
      @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_send_signal_thread(@Unsigned long sig, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_seq_printf(@Unsigned long m, @Unsigned long fmt,
      @Unsigned long fmt_size, @Unsigned long args, @Unsigned long data_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_seq_printf_btf(@Unsigned long m, @Unsigned long ptr,
      @Unsigned long btf_ptr_size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long bpf_seq_read(Ptr<file> file, String buf,
      @Unsigned long size, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_seq_write(@Unsigned long m, @Unsigned long data,
      @Unsigned long len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned Long> bpf_session_cookie() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_session_is_return() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_set_dentry_xattr($arg1, (const u8*)$arg2, (const struct bpf_dynptr*)$arg3, $arg4)")
  public static int bpf_set_dentry_xattr(Ptr<dentry> dentry, String name__str,
      Ptr<bpf_dynptr> value_p, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_set_dentry_xattr_locked($arg1, (const u8*)$arg2, (const struct bpf_dynptr*)$arg3, $arg4)")
  public static int bpf_set_dentry_xattr_locked(Ptr<dentry> dentry, String name__str,
      Ptr<bpf_dynptr> value_p, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_set_hash(@Unsigned long skb, @Unsigned long hash,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_set_hash_invalid(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_set_retval(@Unsigned long retval, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_shim_tramp_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_shim_tramp_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_show_options(Ptr<seq_file> m, Ptr<dentry> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_ancestor_cgroup_id(@Unsigned long sk,
      @Unsigned long ancestor_level, @Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_assign(@Unsigned long skb, @Unsigned long sk,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_assign_tcp_reqsk(Ptr<__sk_buff> s, Ptr<sock> sk,
      Ptr<bpf_tcp_req_attrs> attrs, int attrs__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_sk_base_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_sk_base_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_cgroup_id(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_fullsock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_getsockopt(@Unsigned long sk, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_lookup_assign(@Unsigned long ctx, @Unsigned long sk,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sk_lookup_run_v4((const struct net*)$arg1, $arg2, (const unsigned int)$arg3, (const short unsigned int)$arg4, (const unsigned int)$arg5, (const short unsigned int)$arg6, (const int)$arg7, $arg8)")
  public static boolean bpf_sk_lookup_run_v4(Ptr<net> net, int protocol,
      @Unsigned @OriginalName("__be32") int saddr, @Unsigned @OriginalName("__be16") short sport,
      @Unsigned @OriginalName("__be32") int daddr, @Unsigned short dport, int ifindex,
      Ptr<Ptr<sock>> psk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sk_lookup_run_v6((const struct net*)$arg1, $arg2, (const struct in6_addr*)$arg3, (const short unsigned int)$arg4, (const struct in6_addr*)$arg5, (const short unsigned int)$arg6, (const int)$arg7, $arg8)")
  public static boolean bpf_sk_lookup_run_v6(Ptr<net> net, int protocol, Ptr<in6_addr> saddr,
      @Unsigned @OriginalName("__be16") short sport, Ptr<in6_addr> daddr, @Unsigned short dport,
      int ifindex, Ptr<Ptr<sock>> psk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_lookup_tcp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_lookup_udp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_redirect_hash(@Unsigned long skb, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_redirect_map(@Unsigned long skb, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_release(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_reuseport_detach(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_setsockopt(@Unsigned long sk, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_storage_charge(Ptr<bpf_local_storage_map> smap, Ptr<?> owner,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sk_storage_clone((const struct sock*)$arg1, $arg2)")
  public static int bpf_sk_storage_clone(Ptr<sock> sk, Ptr<sock> newsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_storage_del(Ptr<sock> sk, Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_storage_delete(@Unsigned long map, @Unsigned long sk,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_storage_delete_tracing(@Unsigned long map, @Unsigned long sk,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sk_storage_diag_alloc((const struct nlattr*)$arg1)")
  public static Ptr<bpf_sk_storage_diag> bpf_sk_storage_diag_alloc(Ptr<nlattr> nla_stgs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_storage_diag_free(Ptr<bpf_sk_storage_diag> diag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_storage_diag_put(Ptr<bpf_sk_storage_diag> diag, Ptr<sock> sk,
      Ptr<sk_buff> skb, int stg_array_type, Ptr<java.lang. @Unsigned Integer> res_diag_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_storage_free(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_storage_get(@Unsigned long map, @Unsigned long sk,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sk_storage_get_tracing(@Unsigned long map, @Unsigned long sk,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_sk_storage_map_alloc(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_storage_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_storage_map_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_local_storage_elem> bpf_sk_storage_map_seq_find_next(
      Ptr<bpf_iter_seq_sk_storage_map_info> info, Ptr<bpf_local_storage_elem> prev_selem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_sk_storage_map_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sk_storage_map_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_sk_storage_map_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_storage_map_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<bpf_local_storage>> bpf_sk_storage_ptr(Ptr<?> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sk_storage_tracing_allowed((const struct bpf_prog*)$arg1)")
  public static boolean bpf_sk_storage_tracing_allowed(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_sk_storage_uncharge(Ptr<bpf_local_storage_map> smap, Ptr<?> owner,
      @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_adjust_room(@Unsigned long skb, @Unsigned long len_diff,
      @Unsigned long mode, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_ancestor_cgroup_id(@Unsigned long skb,
      @Unsigned long ancestor_level, @Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_cgroup_classid(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_cgroup_id(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_change_head(@Unsigned long skb, @Unsigned long head_room,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_change_proto(@Unsigned long skb, @Unsigned long proto,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_change_tail(@Unsigned long skb, @Unsigned long new_len,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_change_type(@Unsigned long skb, @Unsigned long pkt_type,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_check_mtu(@Unsigned long skb, @Unsigned long ifindex,
      @Unsigned long mtu_len, @Unsigned long len_diff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_skb_copy($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long bpf_skb_copy(Ptr<?> dst_buff, Ptr<?> skb, @Unsigned long off,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_ecn_set_ce(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_event_output(@Unsigned long skb, @Unsigned long map,
      @Unsigned long flags, @Unsigned long meta, @Unsigned long meta_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_fib_lookup(@Unsigned long skb, @Unsigned long params,
      @Unsigned long plen, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_skb_generic_pop(Ptr<sk_buff> skb, @Unsigned int off, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_skb_generic_push(Ptr<sk_buff> skb, @Unsigned int off, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_skb_get_hash(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_nlattr(@Unsigned long skb, @Unsigned long a,
      @Unsigned long x, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_nlattr_nest(@Unsigned long skb, @Unsigned long a,
      @Unsigned long x, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_pay_offset(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_tunnel_key(@Unsigned long skb, @Unsigned long to,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_tunnel_opt(@Unsigned long skb, @Unsigned long to,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_get_xfrm_state(@Unsigned long skb, @Unsigned long index,
      @Unsigned long to, @Unsigned long size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_bytes(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long to, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_bytes_relative(@Unsigned long skb,
      @Unsigned long offset, @Unsigned long to, @Unsigned long len, @Unsigned long start_header) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_16(@Unsigned long skb, @Unsigned long data,
      @Unsigned long headlen, @Unsigned long offset, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_16_no_cache(@Unsigned long skb,
      @Unsigned long offset, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_32(@Unsigned long skb, @Unsigned long data,
      @Unsigned long headlen, @Unsigned long offset, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_32_no_cache(@Unsigned long skb,
      @Unsigned long offset, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_8(@Unsigned long skb, @Unsigned long data,
      @Unsigned long headlen, @Unsigned long offset, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_load_helper_8_no_cache(@Unsigned long skb,
      @Unsigned long offset, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_skb_net_grow(Ptr<sk_buff> skb, @Unsigned int off, @Unsigned int len_diff,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_skb_net_shrink(Ptr<sk_buff> skb, @Unsigned int off, @Unsigned int len_diff,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_pull_data(@Unsigned long skb, @Unsigned long len,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_set_tstamp(@Unsigned long skb, @Unsigned long tstamp,
      @Unsigned long tstamp_type, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_set_tunnel_key(@Unsigned long skb, @Unsigned long from,
      @Unsigned long size, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_set_tunnel_opt(@Unsigned long skb, @Unsigned long from,
      @Unsigned long size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_store_bytes(@Unsigned long skb, @Unsigned long offset,
      @Unsigned long from, @Unsigned long len, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_under_cgroup(@Unsigned long skb, @Unsigned long map,
      @Unsigned long idx, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_vlan_pop(@Unsigned long skb, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skb_vlan_push(@Unsigned long skb, @Unsigned long vlan_proto,
      @Unsigned long vlan_tci, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_lookup_tcp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_mptcp_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_tcp6_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_tcp_request_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_tcp_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_tcp_timewait_sock(@Unsigned long sk,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_udp6_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_skc_to_unix_sock(@Unsigned long sk, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_skops_hdr_opt_len(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      Ptr<sk_buff> syn_skb, tcp_synack_type synack_type, Ptr<tcp_out_options> opts,
      Ptr<java.lang. @Unsigned Integer> remaining) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_skops_tx_timestamping(Ptr<sock> sk, Ptr<sk_buff> skb, int op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_skops_write_hdr_opt(Ptr<sock> sk, Ptr<sk_buff> skb, Ptr<request_sock> req,
      Ptr<sk_buff> syn_skb, tcp_synack_type synack_type, Ptr<tcp_out_options> opts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_snprintf(@Unsigned long str, @Unsigned long str_size,
      @Unsigned long fmt, @Unsigned long args, @Unsigned long data_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_snprintf_btf(@Unsigned long str, @Unsigned long str_size,
      @Unsigned long ptr, @Unsigned long btf_ptr_size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_addr_getsockopt(@Unsigned long ctx, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sock_addr_set_sun_path($arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_sock_addr_set_sun_path(Ptr<bpf_sock_addr_kern> sa_kern,
      Ptr<java.lang.Character> sun_path, @Unsigned int sun_path__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_addr_setsockopt(@Unsigned long ctx, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_addr_sk_lookup_tcp(@Unsigned long ctx, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_addr_sk_lookup_udp(@Unsigned long ctx, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_addr_skc_lookup_tcp(@Unsigned long ctx,
      @Unsigned long tuple, @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_sock_common_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_sock_convert_ctx_access($arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int bpf_sock_convert_ctx_access(bpf_access_type type, Ptr<bpf_insn> si,
      Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog, Ptr<java.lang. @Unsigned Integer> target_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sock_destroy(Ptr<sock_common> sock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_from_file(@Unsigned long file, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_hash_update(@Unsigned long sops, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_map_update(@Unsigned long sops, @Unsigned long map,
      @Unsigned long key, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_cb_flags_set(@Unsigned long bpf_sock,
      @Unsigned long argval, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sock_ops_enable_tx_tstamp(Ptr<bpf_sock_ops_kern> skops,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_getsockopt(@Unsigned long bpf_sock,
      @Unsigned long level, @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_load_hdr_opt(@Unsigned long bpf_sock,
      @Unsigned long search_res, @Unsigned long len, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_reserve_hdr_opt(@Unsigned long bpf_sock,
      @Unsigned long len, @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_setsockopt(@Unsigned long bpf_sock,
      @Unsigned long level, @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sock_ops_store_hdr_opt(@Unsigned long bpf_sock,
      @Unsigned long from, @Unsigned long len, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sockmap_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_sol_tcp_getsockopt(Ptr<sock> sk, int optname, String optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_spin_unlock(@Unsigned long lock, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_stack_walker(Ptr<?> cookie, @Unsigned long ip, @Unsigned long sp,
      @Unsigned long bp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_stackmap_copy(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_stats_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int bpf_stats_handler(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_stats_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strchr((const u8*)$arg1, $arg2)")
  public static int bpf_strchr(String s__ign, char c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strchrnul((const u8*)$arg1, $arg2)")
  public static int bpf_strchrnul(String s__ign, char c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strcmp((const u8*)$arg1, (const u8*)$arg2)")
  public static int bpf_strcmp(String s1__ign, String s2__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strcspn((const u8*)$arg1, (const u8*)$arg2)")
  public static int bpf_strcspn(String s__ign, String reject__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_stream_page_local_lock(Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_stream_page_put(Ptr<bpf_stream_page> stream_page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_stream_page> bpf_stream_page_replace() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_stream_read(Ptr<bpf_stream> stream, Ptr<?> buf, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_stream_stage_commit(Ptr<bpf_stream_stage> ss, Ptr<bpf_prog> prog,
      bpf_stream_id stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_stream_stage_dump_stack(Ptr<bpf_stream_stage> ss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_stream_stage_free(Ptr<bpf_stream_stage> ss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_stream_stage_init(Ptr<bpf_stream_stage> ss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_stream_stage_printk($arg1, (const u8*)$arg2, $arg3_)")
  public static int bpf_stream_stage_printk(Ptr<bpf_stream_stage> ss, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_stream_vprintk($arg1, (const u8*)$arg2, (const void*)$arg3, $arg4, $arg5)")
  public static int bpf_stream_vprintk(int stream_id, String fmt__str, Ptr<?> args,
      @Unsigned int len__sz, Ptr<?> aux__prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strlen((const u8*)$arg1)")
  public static int bpf_strlen(String s__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strnchr((const u8*)$arg1, $arg2, $arg3)")
  public static int bpf_strnchr(String s__ign, @Unsigned long count, char c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_strncmp(@Unsigned long s1, @Unsigned long s1_sz,
      @Unsigned long s2, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strnlen((const u8*)$arg1, $arg2)")
  public static int bpf_strnlen(String s__ign, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strnstr((const u8*)$arg1, (const u8*)$arg2, $arg3)")
  public static int bpf_strnstr(String s1__ign, String s2__ign, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strrchr((const u8*)$arg1, $arg2)")
  public static int bpf_strrchr(String s__ign, int c) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strspn((const u8*)$arg1, (const u8*)$arg2)")
  public static int bpf_strspn(String s__ign, String accept__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_strstr((const u8*)$arg1, (const u8*)$arg2)")
  public static int bpf_strstr(String s1__ign, String s2__ign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_strtol(@Unsigned long buf, @Unsigned long buf_len,
      @Unsigned long flags, @Unsigned long res, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_strtoul(@Unsigned long buf, @Unsigned long buf_len,
      @Unsigned long flags, @Unsigned long res, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_desc_init(Ptr<bpf_struct_ops_desc> st_ops_desc, Ptr<btf> btf,
      Ptr<bpf_verifier_log> log) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_desc_release(Ptr<bpf_struct_ops_desc> st_ops_desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_struct_ops_desc*)bpf_struct_ops_find($arg1, $arg2))")
  public static Ptr<bpf_struct_ops_desc> bpf_struct_ops_find(Ptr<btf> btf, @Unsigned int type_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_struct_ops_desc*)bpf_struct_ops_find_value($arg1, $arg2))")
  public static Ptr<bpf_struct_ops_desc> bpf_struct_ops_find_value(Ptr<btf> btf,
      @Unsigned int value_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_get((const void*)$arg1)")
  public static boolean bpf_struct_ops_get(Ptr<?> kdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_image_free(Ptr<?> image) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_link_create(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> bpf_struct_ops_map_alloc(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_map_alloc_check(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_struct_ops_map_delete_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_map_get_next_key(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> next_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_map_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_map_link_detach(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_map_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_struct_ops_map_link_fill_link_info(Ptr<bpf_link> link,
      Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int bpf_struct_ops_map_link_poll(Ptr<file> file,
      Ptr<poll_table_struct> pts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_map_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_struct_ops_map_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_map_link_update(Ptr<bpf_link> link, Ptr<bpf_map> new_map,
      Ptr<bpf_map> expected_old_map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_struct_ops_map_lookup_elem(Ptr<bpf_map> map, Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_map_mem_usage((const struct bpf_map*)$arg1)")
  public static @Unsigned long bpf_struct_ops_map_mem_usage(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_struct_ops_map_seq_show_elem(Ptr<bpf_map> map, Ptr<?> key,
      Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_struct_ops_map_sys_lookup_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_struct_ops_map_update_elem(Ptr<bpf_map> map, Ptr<?> key, Ptr<?> value,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_prepare_trampoline($arg1, $arg2, (const struct btf_func_model*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int bpf_struct_ops_prepare_trampoline(Ptr<bpf_tramp_links> tlinks,
      Ptr<bpf_tramp_link> link, Ptr<btf_func_model> model, Ptr<?> stub_func, Ptr<Ptr<?>> _image,
      Ptr<java.lang. @Unsigned Integer> _image_off, boolean allow_alloc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_put((const void*)$arg1)")
  public static void bpf_struct_ops_put(Ptr<?> kdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_supported((const struct bpf_struct_ops*)$arg1, $arg2)")
  public static int bpf_struct_ops_supported(Ptr<bpf_struct_ops> st_ops, @Unsigned int moff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_struct_ops_test_run($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_struct_ops_test_run(Ptr<bpf_prog> prog, Ptr<bpf_attr> kattr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_symlink($arg1, $arg2, $arg3, (const u8*)$arg4)")
  public static int bpf_symlink(Ptr<mnt_idmap> idmap, Ptr<inode> dir, Ptr<dentry> dentry,
      String target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sys_bpf(@Unsigned long cmd, @Unsigned long attr,
      @Unsigned long attr_size, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sys_close(@Unsigned long fd, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_syscall_sysctl_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sysctl_get_current_value(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long buf_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sysctl_get_name(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long buf_len, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sysctl_get_new_value(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long buf_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_sysctl_set_new_value(@Unsigned long ctx, @Unsigned long buf,
      @Unsigned long buf_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_task_acquire(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_task_fd_query((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_task_fd_query(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_task_fd_query_copy((const union bpf_attr*)$arg1, $arg2, $arg3, $arg4, (const u8*)$arg5, $arg6, $arg7)")
  public static int bpf_task_fd_query_copy(Ptr<bpf_attr> attr, Ptr<bpf_attr> uattr,
      @Unsigned int prog_id, @Unsigned int fd_type, String buf, @Unsigned long probe_offset,
      @Unsigned long probe_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_task_from_pid(int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> bpf_task_from_vpid(int vpid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> bpf_task_get_cgroup1(Ptr<task_struct> task, int hierarchy_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_task_pt_regs(@Unsigned long task, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_task_release(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_task_release_dtor(Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_task_storage_delete(@Unsigned long map, @Unsigned long task,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_task_storage_delete_recur(@Unsigned long map,
      @Unsigned long task, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_task_storage_free(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_task_storage_get(@Unsigned long map, @Unsigned long task,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_task_storage_get_recur(@Unsigned long map, @Unsigned long task,
      @Unsigned long value, @Unsigned long flags, @Unsigned long gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long bpf_task_under_cgroup(Ptr<task_struct> task, Ptr<cgroup> ancestor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tc_sk_lookup_tcp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tc_sk_lookup_udp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tc_skc_lookup_tcp(@Unsigned long skb, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_ca_btf_struct_access($arg1, (const struct bpf_reg_state*)$arg2, $arg3, $arg4)")
  public static int bpf_tcp_ca_btf_struct_access(Ptr<bpf_verifier_log> log, Ptr<bpf_reg_state> reg,
      int off, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tcp_ca_cong_avoid(Ptr<sock> sk, @Unsigned int ack, @Unsigned int acked) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_ca_cong_control($arg1, $arg2, $arg3, (const struct rate_sample*)$arg4)")
  public static void bpf_tcp_ca_cong_control(Ptr<sock> sk, @Unsigned int ack, int flag,
      Ptr<rate_sample> rs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tcp_ca_cwnd_event(Ptr<sock> sk, tcp_ca_event ev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_tcp_ca_get_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_tcp_ca_get_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tcp_ca_in_ack_event(Ptr<sock> sk, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ca_init(Ptr<btf> btf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_ca_init_member((const struct btf_type*)$arg1, (const struct btf_member*)$arg2, $arg3, (const void*)$arg4)")
  public static int bpf_tcp_ca_init_member(Ptr<btf_type> t, Ptr<btf_member> member, Ptr<?> kdata,
      Ptr<?> udata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_ca_is_valid_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean bpf_tcp_ca_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_prog> prog, Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ca_kfunc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_tcp_ca_min_tso_segs(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_ca_pkts_acked($arg1, (const struct ack_sample*)$arg2)")
  public static void bpf_tcp_ca_pkts_acked(Ptr<sock> sk, Ptr<ack_sample> sample) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ca_reg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tcp_ca_set_state(Ptr<sock> sk, char new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_tcp_ca_sndbuf_expand(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_tcp_ca_ssthresh(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_tcp_ca_undo_cwnd(Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tcp_ca_unreg(Ptr<?> kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ca_update(Ptr<?> kdata, Ptr<?> old_kdata, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ca_validate(Ptr<?> kdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_check_syncookie(@Unsigned long sk, @Unsigned long iph,
      @Unsigned long iph_len, @Unsigned long th, @Unsigned long th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_gen_syncookie(@Unsigned long sk, @Unsigned long iph,
      @Unsigned long iph_len, @Unsigned long th, @Unsigned long th_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tcp_ingress(Ptr<sock> sk, Ptr<sk_psock> psock, Ptr<sk_msg> msg,
      @Unsigned int apply_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_raw_check_syncookie_ipv4(@Unsigned long iph,
      @Unsigned long th, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_raw_check_syncookie_ipv6(@Unsigned long iph,
      @Unsigned long th, @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_raw_gen_syncookie_ipv4(@Unsigned long iph, @Unsigned long th,
      @Unsigned long th_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_raw_gen_syncookie_ipv6(@Unsigned long iph, @Unsigned long th,
      @Unsigned long th_len, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_tcp_send_ack(@Unsigned long tp, @Unsigned long rcv_nxt,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tcp_sock_convert_ctx_access($arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int bpf_tcp_sock_convert_ctx_access(bpf_access_type type,
      Ptr<bpf_insn> si, Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog,
      Ptr<java.lang. @Unsigned Integer> target_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_tcp_sock_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_test_run(Ptr<bpf_prog> prog, Ptr<?> ctx, @Unsigned int repeat,
      Ptr<java.lang. @Unsigned Integer> retval, Ptr<java.lang. @Unsigned Integer> time,
      boolean xdp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_test_run_xdp_live(Ptr<bpf_prog> prog, Ptr<xdp_buff> ctx,
      @Unsigned int repeat, @Unsigned int batch_size, Ptr<java.lang. @Unsigned Integer> time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_test_timer_continue(Ptr<bpf_test_timer> t, int iterations,
      @Unsigned int repeat, Ptr<java.lang.Integer> err,
      Ptr<java.lang. @Unsigned Integer> duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_this_cpu_ptr(@Unsigned long percpu_ptr, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_throw(@Unsigned long cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_timer_cancel(@Unsigned long timer, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_timer_cancel_and_free(Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart bpf_timer_cb(Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_timer_delete_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_timer_init(@Unsigned long timer, @Unsigned long map,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_timer_set_callback(@Unsigned long timer,
      @Unsigned long callback_fn, @Unsigned long aux, @Unsigned long __ur_1,
      @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_timer_start(@Unsigned long timer, @Unsigned long nsecs,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_token_allow_cmd((const struct bpf_token*)$arg1, $arg2)")
  public static boolean bpf_token_allow_cmd(Ptr<bpf_token> token, bpf_cmd cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_token_allow_map_type((const struct bpf_token*)$arg1, $arg2)")
  public static boolean bpf_token_allow_map_type(Ptr<bpf_token> token, bpf_map_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_token_allow_prog_type((const struct bpf_token*)$arg1, $arg2, $arg3)")
  public static boolean bpf_token_allow_prog_type(Ptr<bpf_token> token, bpf_prog_type prog_type,
      bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_token_capable((const struct bpf_token*)$arg1, $arg2)")
  public static boolean bpf_token_capable(Ptr<bpf_token> token, int cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_token_create(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_token_free(Ptr<bpf_token> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_token> bpf_token_get_from_fd(@Unsigned int ufd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_token_get_info_by_fd($arg1, (const union bpf_attr*)$arg2, $arg3)")
  public static int bpf_token_get_info_by_fd(Ptr<bpf_token> token, Ptr<bpf_attr> attr,
      Ptr<bpf_attr> uattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_token_inc(Ptr<bpf_token> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_token_put(Ptr<bpf_token> token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_token_put_deferred(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_token_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_token_show_fdinfo(Ptr<seq_file> m, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_trace_printk(@Unsigned long fmt, @Unsigned long fmt_size,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run1(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run10(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6, @Unsigned long arg7, @Unsigned long arg8,
      @Unsigned long arg9) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run11(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6, @Unsigned long arg7, @Unsigned long arg8,
      @Unsigned long arg9, @Unsigned long arg10) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run12(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6, @Unsigned long arg7, @Unsigned long arg8,
      @Unsigned long arg9, @Unsigned long arg10, @Unsigned long arg11) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run2(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run3(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run4(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run5(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run6(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run7(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run8(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6, @Unsigned long arg7) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trace_run9(Ptr<bpf_raw_tp_link> link, @Unsigned long arg0,
      @Unsigned long arg1, @Unsigned long arg2, @Unsigned long arg3, @Unsigned long arg4,
      @Unsigned long arg5, @Unsigned long arg6, @Unsigned long arg7, @Unsigned long arg8) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_trace_vprintk(@Unsigned long fmt, @Unsigned long fmt_size,
      @Unsigned long args, @Unsigned long data_len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)bpf_tracing_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> bpf_tracing_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tracing_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tracing_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_tracing_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tracing_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_tracing_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_tracing_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tracing_prog_attach(Ptr<bpf_prog> prog, int tgt_prog_fd,
      @Unsigned int btf_id, @Unsigned long bpf_cookie, bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_tramp_ftrace_ops_func(Ptr<ftrace_ops> ops, ftrace_ops_cmd cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tramp_image_free(Ptr<bpf_tramp_image> im) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_tramp_image_put(Ptr<bpf_tramp_image> im) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_trampoline_enter((const struct bpf_prog*)$arg1)")
  public static @OriginalName("bpf_trampoline_enter_t") Ptr<?> bpf_trampoline_enter(
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_trampoline_exit((const struct bpf_prog*)$arg1)")
  public static @OriginalName("bpf_trampoline_exit_t") Ptr<?> bpf_trampoline_exit(
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_trampoline> bpf_trampoline_get(@Unsigned long key,
      Ptr<bpf_attach_target_info> tgt_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_trampoline_link_cgroup_shim(Ptr<bpf_prog> prog, int cgroup_atype,
      bpf_attach_type attach_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_trampoline_link_prog(Ptr<bpf_tramp_link> link, Ptr<bpf_trampoline> tr,
      Ptr<bpf_prog> tgt_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_trampoline> bpf_trampoline_lookup(@Unsigned long key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trampoline_put(Ptr<bpf_trampoline> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_trampoline_unlink_cgroup_shim(Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_trampoline_unlink_prog(Ptr<bpf_tramp_link> link, Ptr<bpf_trampoline> tr,
      Ptr<bpf_prog> tgt_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_trampoline_update(Ptr<bpf_trampoline> tr, boolean lock_direct_mutex) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_try_get_buffers(Ptr<Ptr<bpf_bprintf_buffers>> bufs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_unlocked_sk_getsockopt(@Unsigned long sk, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_unlocked_sk_setsockopt(@Unsigned long sk, @Unsigned long level,
      @Unsigned long optname, @Unsigned long optval, @Unsigned long optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_unpriv_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int bpf_unpriv_handler(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_update_srh_state(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_uprobe_multi_link_attach((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_uprobe_multi_link_attach(Ptr<bpf_attr> attr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_uprobe_multi_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_uprobe_multi_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_uprobe_multi_link_fill_link_info(Ptr<bpf_link> link,
      Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_uprobe_multi_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_uprobe_multi_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_uprobe_multi_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_user_ringbuf_drain(@Unsigned long map,
      @Unsigned long callback_fn, @Unsigned long callback_ctx, @Unsigned long flags,
      @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_user_rnd_init_once() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_user_rnd_u32(@Unsigned long __ur_1, @Unsigned long __ur_2,
      @Unsigned long __ur_3, @Unsigned long __ur_4, @Unsigned long __ur_5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_verifier_log_write($arg1, (const u8*)$arg2, $arg3_)")
  public static void bpf_verifier_log_write(Ptr<bpf_verifier_env> env, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_verifier_vlog($arg1, (const u8*)$arg2, $arg3)")
  public static void bpf_verifier_vlog(Ptr<bpf_verifier_log> log, String fmt,
      Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_verify_pkcs7_signature(Ptr<bpf_dynptr> data_p, Ptr<bpf_dynptr> sig_p,
      Ptr<bpf_key> trusted_keyring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_vlog_finalize(Ptr<bpf_verifier_log> log,
      Ptr<java.lang. @Unsigned Integer> log_size_actual) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_vlog_init(Ptr<bpf_verifier_log> log, @Unsigned int log_level,
      String log_buf, @Unsigned int log_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_vlog_reset(Ptr<bpf_verifier_log> log, @Unsigned long new_pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_vlog_reverse_ubuf(Ptr<bpf_verifier_log> log, int start, int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_warn_invalid_xdp_action((const struct net_device*)$arg1, (const struct bpf_prog*)$arg2, $arg3)")
  public static void bpf_warn_invalid_xdp_action(Ptr<net_device> dev, Ptr<bpf_prog> prog,
      @Unsigned int act) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_wq_cancel_and_free(Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_wq_delete_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_wq_init(Ptr<bpf_wq> wq, Ptr<?> p__map, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_wq_set_callback_impl($arg1, (int (*)(void*, int*, void*))$arg2, $arg3, $arg4)")
  public static int bpf_wq_set_callback_impl(Ptr<bpf_wq> wq, Ptr<?> callback_fn,
      @Unsigned int flags, Ptr<?> aux__prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_wq_start(Ptr<bpf_wq> wq, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_wq_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_adjust_head(@Unsigned long xdp, @Unsigned long offset,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_adjust_meta(@Unsigned long xdp, @Unsigned long offset,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_adjust_tail(@Unsigned long xdp, @Unsigned long offset,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_check_mtu(@Unsigned long xdp, @Unsigned long ifindex,
      @Unsigned long mtu_len, @Unsigned long len_diff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_copy($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long bpf_xdp_copy(Ptr<?> dst, Ptr<?> ctx, @Unsigned long off,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_xdp_copy_buf(Ptr<xdp_buff> xdp, @Unsigned long off, Ptr<?> buf,
      @Unsigned long len, boolean flush) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_event_output(@Unsigned long xdp, @Unsigned long map,
      @Unsigned long flags, @Unsigned long meta, @Unsigned long meta_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_fib_lookup(@Unsigned long ctx, @Unsigned long params,
      @Unsigned long plen, @Unsigned long flags, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_xdp_frags_shrink_tail(Ptr<xdp_buff> xdp, int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_get_buff_len(@Unsigned long xdp, @Unsigned long __ur_1,
      @Unsigned long __ur_2, @Unsigned long __ur_3, @Unsigned long __ur_4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state> bpf_xdp_get_xfrm_state(Ptr<xdp_md> ctx,
      Ptr<bpf_xfrm_state_opts> opts, @Unsigned int opts__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_link_attach((const union bpf_attr*)$arg1, $arg2)")
  public static int bpf_xdp_link_attach(Ptr<bpf_attr> attr, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_xdp_link_dealloc(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_xdp_link_detach(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_link_fill_link_info((const struct bpf_link*)$arg1, $arg2)")
  public static int bpf_xdp_link_fill_link_info(Ptr<bpf_link> link, Ptr<bpf_link_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_xdp_link_release(Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_link_show_fdinfo((const struct bpf_link*)$arg1, $arg2)")
  public static void bpf_xdp_link_show_fdinfo(Ptr<bpf_link> link, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_xdp_link_update(Ptr<bpf_link> link, Ptr<bpf_prog> new_prog,
      Ptr<bpf_prog> old_prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_load_bytes(@Unsigned long xdp, @Unsigned long offset,
      @Unsigned long buf, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int bpf_xdp_metadata_kfunc_id(int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_metadata_rx_hash((const struct xdp_md*)$arg1, $arg2, $arg3)")
  public static int bpf_xdp_metadata_rx_hash(Ptr<xdp_md> ctx,
      Ptr<java.lang. @Unsigned Integer> hash, Ptr<xdp_rss_hash_type> rss_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_metadata_rx_timestamp((const struct xdp_md*)$arg1, $arg2)")
  public static int bpf_xdp_metadata_rx_timestamp(Ptr<xdp_md> ctx,
      Ptr<java.lang. @Unsigned Long> timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_metadata_rx_vlan_tag((const struct xdp_md*)$arg1, $arg2, $arg3)")
  public static int bpf_xdp_metadata_rx_vlan_tag(Ptr<xdp_md> ctx,
      Ptr<java.lang. @Unsigned @OriginalName("__be16") Short> vlan_proto,
      Ptr<java.lang. @Unsigned Short> vlan_tci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> bpf_xdp_pointer(Ptr<xdp_buff> xdp, @Unsigned int offset, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_redirect(@Unsigned long ifindex, @Unsigned long flags,
      @Unsigned long __ur_1, @Unsigned long __ur_2, @Unsigned long __ur_3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_redirect_map(@Unsigned long map, @Unsigned long key,
      @Unsigned long flags, @Unsigned long __ur_1, @Unsigned long __ur_2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_sk_lookup_tcp(@Unsigned long ctx, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_sk_lookup_udp(@Unsigned long ctx, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_skc_lookup_tcp(@Unsigned long ctx, @Unsigned long tuple,
      @Unsigned long len, @Unsigned long netns_id, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("bpf_xdp_sock_convert_ctx_access($arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int bpf_xdp_sock_convert_ctx_access(bpf_access_type type,
      Ptr<bpf_insn> si, Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog,
      Ptr<java.lang. @Unsigned Integer> target_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean bpf_xdp_sock_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long bpf_xdp_store_bytes(@Unsigned long xdp, @Unsigned long offset,
      @Unsigned long buf, @Unsigned long len, @Unsigned long __ur_1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void bpf_xdp_xfrm_state_release(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int bpf_xmit(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_event_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_event_map extends Struct {
    public Ptr<tracepoint> tp;

    public Ptr<?> bpf_func;

    public @Unsigned int num_args;

    public @Unsigned int writable_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_run_ctx extends Struct {
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_array extends Struct {
    public callback_head rcu;

    public bpf_prog_array_item @Size(0) [] items;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_insn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_insn extends Struct {
    public char code;

    public char dst_reg;

    public char src_reg;

    public short off;

    public int imm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_cgroup_iter_order"
  )
  public enum bpf_cgroup_iter_order implements Enum<bpf_cgroup_iter_order>, TypedEnum<bpf_cgroup_iter_order, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_CGROUP_ITER_ORDER_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_CGROUP_ITER_ORDER_UNSPEC"
    )
    BPF_CGROUP_ITER_ORDER_UNSPEC,

    /**
     * {@code BPF_CGROUP_ITER_SELF_ONLY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_CGROUP_ITER_SELF_ONLY"
    )
    BPF_CGROUP_ITER_SELF_ONLY,

    /**
     * {@code BPF_CGROUP_ITER_DESCENDANTS_PRE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_CGROUP_ITER_DESCENDANTS_PRE"
    )
    BPF_CGROUP_ITER_DESCENDANTS_PRE,

    /**
     * {@code BPF_CGROUP_ITER_DESCENDANTS_POST = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_CGROUP_ITER_DESCENDANTS_POST"
    )
    BPF_CGROUP_ITER_DESCENDANTS_POST,

    /**
     * {@code BPF_CGROUP_ITER_ANCESTORS_UP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_CGROUP_ITER_ANCESTORS_UP"
    )
    BPF_CGROUP_ITER_ANCESTORS_UP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_map_type"
  )
  public enum bpf_map_type implements Enum<bpf_map_type>, TypedEnum<bpf_map_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MAP_TYPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_MAP_TYPE_UNSPEC"
    )
    BPF_MAP_TYPE_UNSPEC,

    /**
     * {@code BPF_MAP_TYPE_HASH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_MAP_TYPE_HASH"
    )
    BPF_MAP_TYPE_HASH,

    /**
     * {@code BPF_MAP_TYPE_ARRAY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_MAP_TYPE_ARRAY"
    )
    BPF_MAP_TYPE_ARRAY,

    /**
     * {@code BPF_MAP_TYPE_PROG_ARRAY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_MAP_TYPE_PROG_ARRAY"
    )
    BPF_MAP_TYPE_PROG_ARRAY,

    /**
     * {@code BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_MAP_TYPE_PERF_EVENT_ARRAY"
    )
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,

    /**
     * {@code BPF_MAP_TYPE_PERCPU_HASH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_MAP_TYPE_PERCPU_HASH"
    )
    BPF_MAP_TYPE_PERCPU_HASH,

    /**
     * {@code BPF_MAP_TYPE_PERCPU_ARRAY = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_MAP_TYPE_PERCPU_ARRAY"
    )
    BPF_MAP_TYPE_PERCPU_ARRAY,

    /**
     * {@code BPF_MAP_TYPE_STACK_TRACE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_MAP_TYPE_STACK_TRACE"
    )
    BPF_MAP_TYPE_STACK_TRACE,

    /**
     * {@code BPF_MAP_TYPE_CGROUP_ARRAY = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_MAP_TYPE_CGROUP_ARRAY"
    )
    BPF_MAP_TYPE_CGROUP_ARRAY,

    /**
     * {@code BPF_MAP_TYPE_LRU_HASH = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_MAP_TYPE_LRU_HASH"
    )
    BPF_MAP_TYPE_LRU_HASH,

    /**
     * {@code BPF_MAP_TYPE_LRU_PERCPU_HASH = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_MAP_TYPE_LRU_PERCPU_HASH"
    )
    BPF_MAP_TYPE_LRU_PERCPU_HASH,

    /**
     * {@code BPF_MAP_TYPE_LPM_TRIE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_MAP_TYPE_LPM_TRIE"
    )
    BPF_MAP_TYPE_LPM_TRIE,

    /**
     * {@code BPF_MAP_TYPE_ARRAY_OF_MAPS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_MAP_TYPE_ARRAY_OF_MAPS"
    )
    BPF_MAP_TYPE_ARRAY_OF_MAPS,

    /**
     * {@code BPF_MAP_TYPE_HASH_OF_MAPS = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_MAP_TYPE_HASH_OF_MAPS"
    )
    BPF_MAP_TYPE_HASH_OF_MAPS,

    /**
     * {@code BPF_MAP_TYPE_DEVMAP = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_MAP_TYPE_DEVMAP"
    )
    BPF_MAP_TYPE_DEVMAP,

    /**
     * {@code BPF_MAP_TYPE_SOCKMAP = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BPF_MAP_TYPE_SOCKMAP"
    )
    BPF_MAP_TYPE_SOCKMAP,

    /**
     * {@code BPF_MAP_TYPE_CPUMAP = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_MAP_TYPE_CPUMAP"
    )
    BPF_MAP_TYPE_CPUMAP,

    /**
     * {@code BPF_MAP_TYPE_XSKMAP = 17}
     */
    @EnumMember(
        value = 17L,
        name = "BPF_MAP_TYPE_XSKMAP"
    )
    BPF_MAP_TYPE_XSKMAP,

    /**
     * {@code BPF_MAP_TYPE_SOCKHASH = 18}
     */
    @EnumMember(
        value = 18L,
        name = "BPF_MAP_TYPE_SOCKHASH"
    )
    BPF_MAP_TYPE_SOCKHASH,

    /**
     * {@code BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED"
    )
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,

    /**
     * {@code BPF_MAP_TYPE_CGROUP_STORAGE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_MAP_TYPE_CGROUP_STORAGE"
    )
    BPF_MAP_TYPE_CGROUP_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20}
     */
    @EnumMember(
        value = 20L,
        name = "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY"
    )
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,

    /**
     * {@code BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED"
    )
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,

    /**
     * {@code BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE"
    )
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_QUEUE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "BPF_MAP_TYPE_QUEUE"
    )
    BPF_MAP_TYPE_QUEUE,

    /**
     * {@code BPF_MAP_TYPE_STACK = 23}
     */
    @EnumMember(
        value = 23L,
        name = "BPF_MAP_TYPE_STACK"
    )
    BPF_MAP_TYPE_STACK,

    /**
     * {@code BPF_MAP_TYPE_SK_STORAGE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "BPF_MAP_TYPE_SK_STORAGE"
    )
    BPF_MAP_TYPE_SK_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_DEVMAP_HASH = 25}
     */
    @EnumMember(
        value = 25L,
        name = "BPF_MAP_TYPE_DEVMAP_HASH"
    )
    BPF_MAP_TYPE_DEVMAP_HASH,

    /**
     * {@code BPF_MAP_TYPE_STRUCT_OPS = 26}
     */
    @EnumMember(
        value = 26L,
        name = "BPF_MAP_TYPE_STRUCT_OPS"
    )
    BPF_MAP_TYPE_STRUCT_OPS,

    /**
     * {@code BPF_MAP_TYPE_RINGBUF = 27}
     */
    @EnumMember(
        value = 27L,
        name = "BPF_MAP_TYPE_RINGBUF"
    )
    BPF_MAP_TYPE_RINGBUF,

    /**
     * {@code BPF_MAP_TYPE_INODE_STORAGE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_MAP_TYPE_INODE_STORAGE"
    )
    BPF_MAP_TYPE_INODE_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_TASK_STORAGE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "BPF_MAP_TYPE_TASK_STORAGE"
    )
    BPF_MAP_TYPE_TASK_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_BLOOM_FILTER = 30}
     */
    @EnumMember(
        value = 30L,
        name = "BPF_MAP_TYPE_BLOOM_FILTER"
    )
    BPF_MAP_TYPE_BLOOM_FILTER,

    /**
     * {@code BPF_MAP_TYPE_USER_RINGBUF = 31}
     */
    @EnumMember(
        value = 31L,
        name = "BPF_MAP_TYPE_USER_RINGBUF"
    )
    BPF_MAP_TYPE_USER_RINGBUF,

    /**
     * {@code BPF_MAP_TYPE_CGRP_STORAGE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_MAP_TYPE_CGRP_STORAGE"
    )
    BPF_MAP_TYPE_CGRP_STORAGE,

    /**
     * {@code BPF_MAP_TYPE_ARENA = 33}
     */
    @EnumMember(
        value = 33L,
        name = "BPF_MAP_TYPE_ARENA"
    )
    BPF_MAP_TYPE_ARENA,

    /**
     * {@code __MAX_BPF_MAP_TYPE = 34}
     */
    @EnumMember(
        value = 34L,
        name = "__MAX_BPF_MAP_TYPE"
    )
    __MAX_BPF_MAP_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_prog_type"
  )
  public enum bpf_prog_type implements Enum<bpf_prog_type>, TypedEnum<bpf_prog_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_PROG_TYPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_PROG_TYPE_UNSPEC"
    )
    BPF_PROG_TYPE_UNSPEC,

    /**
     * {@code BPF_PROG_TYPE_SOCKET_FILTER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_PROG_TYPE_SOCKET_FILTER"
    )
    BPF_PROG_TYPE_SOCKET_FILTER,

    /**
     * {@code BPF_PROG_TYPE_KPROBE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_PROG_TYPE_KPROBE"
    )
    BPF_PROG_TYPE_KPROBE,

    /**
     * {@code BPF_PROG_TYPE_SCHED_CLS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_PROG_TYPE_SCHED_CLS"
    )
    BPF_PROG_TYPE_SCHED_CLS,

    /**
     * {@code BPF_PROG_TYPE_SCHED_ACT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_PROG_TYPE_SCHED_ACT"
    )
    BPF_PROG_TYPE_SCHED_ACT,

    /**
     * {@code BPF_PROG_TYPE_TRACEPOINT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_PROG_TYPE_TRACEPOINT"
    )
    BPF_PROG_TYPE_TRACEPOINT,

    /**
     * {@code BPF_PROG_TYPE_XDP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_PROG_TYPE_XDP"
    )
    BPF_PROG_TYPE_XDP,

    /**
     * {@code BPF_PROG_TYPE_PERF_EVENT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_PROG_TYPE_PERF_EVENT"
    )
    BPF_PROG_TYPE_PERF_EVENT,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_SKB = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_PROG_TYPE_CGROUP_SKB"
    )
    BPF_PROG_TYPE_CGROUP_SKB,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_SOCK = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_PROG_TYPE_CGROUP_SOCK"
    )
    BPF_PROG_TYPE_CGROUP_SOCK,

    /**
     * {@code BPF_PROG_TYPE_LWT_IN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_PROG_TYPE_LWT_IN"
    )
    BPF_PROG_TYPE_LWT_IN,

    /**
     * {@code BPF_PROG_TYPE_LWT_OUT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_PROG_TYPE_LWT_OUT"
    )
    BPF_PROG_TYPE_LWT_OUT,

    /**
     * {@code BPF_PROG_TYPE_LWT_XMIT = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_PROG_TYPE_LWT_XMIT"
    )
    BPF_PROG_TYPE_LWT_XMIT,

    /**
     * {@code BPF_PROG_TYPE_SOCK_OPS = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_PROG_TYPE_SOCK_OPS"
    )
    BPF_PROG_TYPE_SOCK_OPS,

    /**
     * {@code BPF_PROG_TYPE_SK_SKB = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_PROG_TYPE_SK_SKB"
    )
    BPF_PROG_TYPE_SK_SKB,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_DEVICE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BPF_PROG_TYPE_CGROUP_DEVICE"
    )
    BPF_PROG_TYPE_CGROUP_DEVICE,

    /**
     * {@code BPF_PROG_TYPE_SK_MSG = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_PROG_TYPE_SK_MSG"
    )
    BPF_PROG_TYPE_SK_MSG,

    /**
     * {@code BPF_PROG_TYPE_RAW_TRACEPOINT = 17}
     */
    @EnumMember(
        value = 17L,
        name = "BPF_PROG_TYPE_RAW_TRACEPOINT"
    )
    BPF_PROG_TYPE_RAW_TRACEPOINT,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18}
     */
    @EnumMember(
        value = 18L,
        name = "BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
    )
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,

    /**
     * {@code BPF_PROG_TYPE_LWT_SEG6LOCAL = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_PROG_TYPE_LWT_SEG6LOCAL"
    )
    BPF_PROG_TYPE_LWT_SEG6LOCAL,

    /**
     * {@code BPF_PROG_TYPE_LIRC_MODE2 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "BPF_PROG_TYPE_LIRC_MODE2"
    )
    BPF_PROG_TYPE_LIRC_MODE2,

    /**
     * {@code BPF_PROG_TYPE_SK_REUSEPORT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_PROG_TYPE_SK_REUSEPORT"
    )
    BPF_PROG_TYPE_SK_REUSEPORT,

    /**
     * {@code BPF_PROG_TYPE_FLOW_DISSECTOR = 22}
     */
    @EnumMember(
        value = 22L,
        name = "BPF_PROG_TYPE_FLOW_DISSECTOR"
    )
    BPF_PROG_TYPE_FLOW_DISSECTOR,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_SYSCTL = 23}
     */
    @EnumMember(
        value = 23L,
        name = "BPF_PROG_TYPE_CGROUP_SYSCTL"
    )
    BPF_PROG_TYPE_CGROUP_SYSCTL,

    /**
     * {@code BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE"
    )
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,

    /**
     * {@code BPF_PROG_TYPE_CGROUP_SOCKOPT = 25}
     */
    @EnumMember(
        value = 25L,
        name = "BPF_PROG_TYPE_CGROUP_SOCKOPT"
    )
    BPF_PROG_TYPE_CGROUP_SOCKOPT,

    /**
     * {@code BPF_PROG_TYPE_TRACING = 26}
     */
    @EnumMember(
        value = 26L,
        name = "BPF_PROG_TYPE_TRACING"
    )
    BPF_PROG_TYPE_TRACING,

    /**
     * {@code BPF_PROG_TYPE_STRUCT_OPS = 27}
     */
    @EnumMember(
        value = 27L,
        name = "BPF_PROG_TYPE_STRUCT_OPS"
    )
    BPF_PROG_TYPE_STRUCT_OPS,

    /**
     * {@code BPF_PROG_TYPE_EXT = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_PROG_TYPE_EXT"
    )
    BPF_PROG_TYPE_EXT,

    /**
     * {@code BPF_PROG_TYPE_LSM = 29}
     */
    @EnumMember(
        value = 29L,
        name = "BPF_PROG_TYPE_LSM"
    )
    BPF_PROG_TYPE_LSM,

    /**
     * {@code BPF_PROG_TYPE_SK_LOOKUP = 30}
     */
    @EnumMember(
        value = 30L,
        name = "BPF_PROG_TYPE_SK_LOOKUP"
    )
    BPF_PROG_TYPE_SK_LOOKUP,

    /**
     * {@code BPF_PROG_TYPE_SYSCALL = 31}
     */
    @EnumMember(
        value = 31L,
        name = "BPF_PROG_TYPE_SYSCALL"
    )
    BPF_PROG_TYPE_SYSCALL,

    /**
     * {@code BPF_PROG_TYPE_NETFILTER = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_PROG_TYPE_NETFILTER"
    )
    BPF_PROG_TYPE_NETFILTER,

    /**
     * {@code __MAX_BPF_PROG_TYPE = 33}
     */
    @EnumMember(
        value = 33L,
        name = "__MAX_BPF_PROG_TYPE"
    )
    __MAX_BPF_PROG_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_attach_type"
  )
  public enum bpf_attach_type implements Enum<bpf_attach_type>, TypedEnum<bpf_attach_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_CGROUP_INET_INGRESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_CGROUP_INET_INGRESS"
    )
    BPF_CGROUP_INET_INGRESS,

    /**
     * {@code BPF_CGROUP_INET_EGRESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_CGROUP_INET_EGRESS"
    )
    BPF_CGROUP_INET_EGRESS,

    /**
     * {@code BPF_CGROUP_INET_SOCK_CREATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_CGROUP_INET_SOCK_CREATE"
    )
    BPF_CGROUP_INET_SOCK_CREATE,

    /**
     * {@code BPF_CGROUP_SOCK_OPS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_CGROUP_SOCK_OPS"
    )
    BPF_CGROUP_SOCK_OPS,

    /**
     * {@code BPF_SK_SKB_STREAM_PARSER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_SK_SKB_STREAM_PARSER"
    )
    BPF_SK_SKB_STREAM_PARSER,

    /**
     * {@code BPF_SK_SKB_STREAM_VERDICT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_SK_SKB_STREAM_VERDICT"
    )
    BPF_SK_SKB_STREAM_VERDICT,

    /**
     * {@code BPF_CGROUP_DEVICE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_CGROUP_DEVICE"
    )
    BPF_CGROUP_DEVICE,

    /**
     * {@code BPF_SK_MSG_VERDICT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_SK_MSG_VERDICT"
    )
    BPF_SK_MSG_VERDICT,

    /**
     * {@code BPF_CGROUP_INET4_BIND = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_CGROUP_INET4_BIND"
    )
    BPF_CGROUP_INET4_BIND,

    /**
     * {@code BPF_CGROUP_INET6_BIND = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_CGROUP_INET6_BIND"
    )
    BPF_CGROUP_INET6_BIND,

    /**
     * {@code BPF_CGROUP_INET4_CONNECT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_CGROUP_INET4_CONNECT"
    )
    BPF_CGROUP_INET4_CONNECT,

    /**
     * {@code BPF_CGROUP_INET6_CONNECT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_CGROUP_INET6_CONNECT"
    )
    BPF_CGROUP_INET6_CONNECT,

    /**
     * {@code BPF_CGROUP_INET4_POST_BIND = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_CGROUP_INET4_POST_BIND"
    )
    BPF_CGROUP_INET4_POST_BIND,

    /**
     * {@code BPF_CGROUP_INET6_POST_BIND = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_CGROUP_INET6_POST_BIND"
    )
    BPF_CGROUP_INET6_POST_BIND,

    /**
     * {@code BPF_CGROUP_UDP4_SENDMSG = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_CGROUP_UDP4_SENDMSG"
    )
    BPF_CGROUP_UDP4_SENDMSG,

    /**
     * {@code BPF_CGROUP_UDP6_SENDMSG = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BPF_CGROUP_UDP6_SENDMSG"
    )
    BPF_CGROUP_UDP6_SENDMSG,

    /**
     * {@code BPF_LIRC_MODE2 = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_LIRC_MODE2"
    )
    BPF_LIRC_MODE2,

    /**
     * {@code BPF_FLOW_DISSECTOR = 17}
     */
    @EnumMember(
        value = 17L,
        name = "BPF_FLOW_DISSECTOR"
    )
    BPF_FLOW_DISSECTOR,

    /**
     * {@code BPF_CGROUP_SYSCTL = 18}
     */
    @EnumMember(
        value = 18L,
        name = "BPF_CGROUP_SYSCTL"
    )
    BPF_CGROUP_SYSCTL,

    /**
     * {@code BPF_CGROUP_UDP4_RECVMSG = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_CGROUP_UDP4_RECVMSG"
    )
    BPF_CGROUP_UDP4_RECVMSG,

    /**
     * {@code BPF_CGROUP_UDP6_RECVMSG = 20}
     */
    @EnumMember(
        value = 20L,
        name = "BPF_CGROUP_UDP6_RECVMSG"
    )
    BPF_CGROUP_UDP6_RECVMSG,

    /**
     * {@code BPF_CGROUP_GETSOCKOPT = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_CGROUP_GETSOCKOPT"
    )
    BPF_CGROUP_GETSOCKOPT,

    /**
     * {@code BPF_CGROUP_SETSOCKOPT = 22}
     */
    @EnumMember(
        value = 22L,
        name = "BPF_CGROUP_SETSOCKOPT"
    )
    BPF_CGROUP_SETSOCKOPT,

    /**
     * {@code BPF_TRACE_RAW_TP = 23}
     */
    @EnumMember(
        value = 23L,
        name = "BPF_TRACE_RAW_TP"
    )
    BPF_TRACE_RAW_TP,

    /**
     * {@code BPF_TRACE_FENTRY = 24}
     */
    @EnumMember(
        value = 24L,
        name = "BPF_TRACE_FENTRY"
    )
    BPF_TRACE_FENTRY,

    /**
     * {@code BPF_TRACE_FEXIT = 25}
     */
    @EnumMember(
        value = 25L,
        name = "BPF_TRACE_FEXIT"
    )
    BPF_TRACE_FEXIT,

    /**
     * {@code BPF_MODIFY_RETURN = 26}
     */
    @EnumMember(
        value = 26L,
        name = "BPF_MODIFY_RETURN"
    )
    BPF_MODIFY_RETURN,

    /**
     * {@code BPF_LSM_MAC = 27}
     */
    @EnumMember(
        value = 27L,
        name = "BPF_LSM_MAC"
    )
    BPF_LSM_MAC,

    /**
     * {@code BPF_TRACE_ITER = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_TRACE_ITER"
    )
    BPF_TRACE_ITER,

    /**
     * {@code BPF_CGROUP_INET4_GETPEERNAME = 29}
     */
    @EnumMember(
        value = 29L,
        name = "BPF_CGROUP_INET4_GETPEERNAME"
    )
    BPF_CGROUP_INET4_GETPEERNAME,

    /**
     * {@code BPF_CGROUP_INET6_GETPEERNAME = 30}
     */
    @EnumMember(
        value = 30L,
        name = "BPF_CGROUP_INET6_GETPEERNAME"
    )
    BPF_CGROUP_INET6_GETPEERNAME,

    /**
     * {@code BPF_CGROUP_INET4_GETSOCKNAME = 31}
     */
    @EnumMember(
        value = 31L,
        name = "BPF_CGROUP_INET4_GETSOCKNAME"
    )
    BPF_CGROUP_INET4_GETSOCKNAME,

    /**
     * {@code BPF_CGROUP_INET6_GETSOCKNAME = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_CGROUP_INET6_GETSOCKNAME"
    )
    BPF_CGROUP_INET6_GETSOCKNAME,

    /**
     * {@code BPF_XDP_DEVMAP = 33}
     */
    @EnumMember(
        value = 33L,
        name = "BPF_XDP_DEVMAP"
    )
    BPF_XDP_DEVMAP,

    /**
     * {@code BPF_CGROUP_INET_SOCK_RELEASE = 34}
     */
    @EnumMember(
        value = 34L,
        name = "BPF_CGROUP_INET_SOCK_RELEASE"
    )
    BPF_CGROUP_INET_SOCK_RELEASE,

    /**
     * {@code BPF_XDP_CPUMAP = 35}
     */
    @EnumMember(
        value = 35L,
        name = "BPF_XDP_CPUMAP"
    )
    BPF_XDP_CPUMAP,

    /**
     * {@code BPF_SK_LOOKUP = 36}
     */
    @EnumMember(
        value = 36L,
        name = "BPF_SK_LOOKUP"
    )
    BPF_SK_LOOKUP,

    /**
     * {@code BPF_XDP = 37}
     */
    @EnumMember(
        value = 37L,
        name = "BPF_XDP"
    )
    BPF_XDP,

    /**
     * {@code BPF_SK_SKB_VERDICT = 38}
     */
    @EnumMember(
        value = 38L,
        name = "BPF_SK_SKB_VERDICT"
    )
    BPF_SK_SKB_VERDICT,

    /**
     * {@code BPF_SK_REUSEPORT_SELECT = 39}
     */
    @EnumMember(
        value = 39L,
        name = "BPF_SK_REUSEPORT_SELECT"
    )
    BPF_SK_REUSEPORT_SELECT,

    /**
     * {@code BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE"
    )
    BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,

    /**
     * {@code BPF_PERF_EVENT = 41}
     */
    @EnumMember(
        value = 41L,
        name = "BPF_PERF_EVENT"
    )
    BPF_PERF_EVENT,

    /**
     * {@code BPF_TRACE_KPROBE_MULTI = 42}
     */
    @EnumMember(
        value = 42L,
        name = "BPF_TRACE_KPROBE_MULTI"
    )
    BPF_TRACE_KPROBE_MULTI,

    /**
     * {@code BPF_LSM_CGROUP = 43}
     */
    @EnumMember(
        value = 43L,
        name = "BPF_LSM_CGROUP"
    )
    BPF_LSM_CGROUP,

    /**
     * {@code BPF_STRUCT_OPS = 44}
     */
    @EnumMember(
        value = 44L,
        name = "BPF_STRUCT_OPS"
    )
    BPF_STRUCT_OPS,

    /**
     * {@code BPF_NETFILTER = 45}
     */
    @EnumMember(
        value = 45L,
        name = "BPF_NETFILTER"
    )
    BPF_NETFILTER,

    /**
     * {@code BPF_TCX_INGRESS = 46}
     */
    @EnumMember(
        value = 46L,
        name = "BPF_TCX_INGRESS"
    )
    BPF_TCX_INGRESS,

    /**
     * {@code BPF_TCX_EGRESS = 47}
     */
    @EnumMember(
        value = 47L,
        name = "BPF_TCX_EGRESS"
    )
    BPF_TCX_EGRESS,

    /**
     * {@code BPF_TRACE_UPROBE_MULTI = 48}
     */
    @EnumMember(
        value = 48L,
        name = "BPF_TRACE_UPROBE_MULTI"
    )
    BPF_TRACE_UPROBE_MULTI,

    /**
     * {@code BPF_CGROUP_UNIX_CONNECT = 49}
     */
    @EnumMember(
        value = 49L,
        name = "BPF_CGROUP_UNIX_CONNECT"
    )
    BPF_CGROUP_UNIX_CONNECT,

    /**
     * {@code BPF_CGROUP_UNIX_SENDMSG = 50}
     */
    @EnumMember(
        value = 50L,
        name = "BPF_CGROUP_UNIX_SENDMSG"
    )
    BPF_CGROUP_UNIX_SENDMSG,

    /**
     * {@code BPF_CGROUP_UNIX_RECVMSG = 51}
     */
    @EnumMember(
        value = 51L,
        name = "BPF_CGROUP_UNIX_RECVMSG"
    )
    BPF_CGROUP_UNIX_RECVMSG,

    /**
     * {@code BPF_CGROUP_UNIX_GETPEERNAME = 52}
     */
    @EnumMember(
        value = 52L,
        name = "BPF_CGROUP_UNIX_GETPEERNAME"
    )
    BPF_CGROUP_UNIX_GETPEERNAME,

    /**
     * {@code BPF_CGROUP_UNIX_GETSOCKNAME = 53}
     */
    @EnumMember(
        value = 53L,
        name = "BPF_CGROUP_UNIX_GETSOCKNAME"
    )
    BPF_CGROUP_UNIX_GETSOCKNAME,

    /**
     * {@code BPF_NETKIT_PRIMARY = 54}
     */
    @EnumMember(
        value = 54L,
        name = "BPF_NETKIT_PRIMARY"
    )
    BPF_NETKIT_PRIMARY,

    /**
     * {@code BPF_NETKIT_PEER = 55}
     */
    @EnumMember(
        value = 55L,
        name = "BPF_NETKIT_PEER"
    )
    BPF_NETKIT_PEER,

    /**
     * {@code BPF_TRACE_KPROBE_SESSION = 56}
     */
    @EnumMember(
        value = 56L,
        name = "BPF_TRACE_KPROBE_SESSION"
    )
    BPF_TRACE_KPROBE_SESSION,

    /**
     * {@code BPF_TRACE_UPROBE_SESSION = 57}
     */
    @EnumMember(
        value = 57L,
        name = "BPF_TRACE_UPROBE_SESSION"
    )
    BPF_TRACE_UPROBE_SESSION,

    /**
     * {@code __MAX_BPF_ATTACH_TYPE = 58}
     */
    @EnumMember(
        value = 58L,
        name = "__MAX_BPF_ATTACH_TYPE"
    )
    __MAX_BPF_ATTACH_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_link_type"
  )
  public enum bpf_link_type implements Enum<bpf_link_type>, TypedEnum<bpf_link_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_LINK_TYPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_LINK_TYPE_UNSPEC"
    )
    BPF_LINK_TYPE_UNSPEC,

    /**
     * {@code BPF_LINK_TYPE_RAW_TRACEPOINT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_LINK_TYPE_RAW_TRACEPOINT"
    )
    BPF_LINK_TYPE_RAW_TRACEPOINT,

    /**
     * {@code BPF_LINK_TYPE_TRACING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_LINK_TYPE_TRACING"
    )
    BPF_LINK_TYPE_TRACING,

    /**
     * {@code BPF_LINK_TYPE_CGROUP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_LINK_TYPE_CGROUP"
    )
    BPF_LINK_TYPE_CGROUP,

    /**
     * {@code BPF_LINK_TYPE_ITER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_LINK_TYPE_ITER"
    )
    BPF_LINK_TYPE_ITER,

    /**
     * {@code BPF_LINK_TYPE_NETNS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_LINK_TYPE_NETNS"
    )
    BPF_LINK_TYPE_NETNS,

    /**
     * {@code BPF_LINK_TYPE_XDP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_LINK_TYPE_XDP"
    )
    BPF_LINK_TYPE_XDP,

    /**
     * {@code BPF_LINK_TYPE_PERF_EVENT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_LINK_TYPE_PERF_EVENT"
    )
    BPF_LINK_TYPE_PERF_EVENT,

    /**
     * {@code BPF_LINK_TYPE_KPROBE_MULTI = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_LINK_TYPE_KPROBE_MULTI"
    )
    BPF_LINK_TYPE_KPROBE_MULTI,

    /**
     * {@code BPF_LINK_TYPE_STRUCT_OPS = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_LINK_TYPE_STRUCT_OPS"
    )
    BPF_LINK_TYPE_STRUCT_OPS,

    /**
     * {@code BPF_LINK_TYPE_NETFILTER = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_LINK_TYPE_NETFILTER"
    )
    BPF_LINK_TYPE_NETFILTER,

    /**
     * {@code BPF_LINK_TYPE_TCX = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_LINK_TYPE_TCX"
    )
    BPF_LINK_TYPE_TCX,

    /**
     * {@code BPF_LINK_TYPE_UPROBE_MULTI = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_LINK_TYPE_UPROBE_MULTI"
    )
    BPF_LINK_TYPE_UPROBE_MULTI,

    /**
     * {@code BPF_LINK_TYPE_NETKIT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_LINK_TYPE_NETKIT"
    )
    BPF_LINK_TYPE_NETKIT,

    /**
     * {@code BPF_LINK_TYPE_SOCKMAP = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_LINK_TYPE_SOCKMAP"
    )
    BPF_LINK_TYPE_SOCKMAP,

    /**
     * {@code __MAX_BPF_LINK_TYPE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "__MAX_BPF_LINK_TYPE"
    )
    __MAX_BPF_LINK_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union bpf_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_attr extends Union {
    public anon_member_of_bpf_attr anon0;

    public anon_member_of_bpf_attr anon1;

    public batch_of_bpf_attr batch;

    public anon_member_of_bpf_attr anon3;

    public anon_member_of_bpf_attr anon4;

    public anon_member_of_bpf_attr anon5;

    public test_of_bpf_attr test;

    public anon_member_of_bpf_attr anon7;

    public info_of_bpf_attr info;

    public query_of_bpf_attr query;

    public raw_tracepoint_of_bpf_attr raw_tracepoint;

    public anon_member_of_bpf_attr anon11;

    public task_fd_query_of_bpf_attr task_fd_query;

    public link_create_of_bpf_attr link_create;

    public link_update_of_bpf_attr link_update;

    public link_detach_of_bpf_attr link_detach;

    public enable_stats_of_bpf_attr enable_stats;

    public iter_create_of_bpf_attr iter_create;

    public prog_bind_map_of_bpf_attr prog_bind_map;

    public token_create_of_bpf_attr token_create;

    public prog_stream_read_of_bpf_attr prog_stream_read;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_func_id"
  )
  public enum bpf_func_id implements Enum<bpf_func_id>, TypedEnum<bpf_func_id, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_FUNC_unspec = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_FUNC_unspec"
    )
    BPF_FUNC_unspec,

    /**
     * {@code BPF_FUNC_map_lookup_elem = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_FUNC_map_lookup_elem"
    )
    BPF_FUNC_map_lookup_elem,

    /**
     * {@code BPF_FUNC_map_update_elem = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_FUNC_map_update_elem"
    )
    BPF_FUNC_map_update_elem,

    /**
     * {@code BPF_FUNC_map_delete_elem = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_FUNC_map_delete_elem"
    )
    BPF_FUNC_map_delete_elem,

    /**
     * {@code BPF_FUNC_probe_read = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_FUNC_probe_read"
    )
    BPF_FUNC_probe_read,

    /**
     * {@code BPF_FUNC_ktime_get_ns = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_FUNC_ktime_get_ns"
    )
    BPF_FUNC_ktime_get_ns,

    /**
     * {@code BPF_FUNC_trace_printk = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_FUNC_trace_printk"
    )
    BPF_FUNC_trace_printk,

    /**
     * {@code BPF_FUNC_get_prandom_u32 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_FUNC_get_prandom_u32"
    )
    BPF_FUNC_get_prandom_u32,

    /**
     * {@code BPF_FUNC_get_smp_processor_id = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_FUNC_get_smp_processor_id"
    )
    BPF_FUNC_get_smp_processor_id,

    /**
     * {@code BPF_FUNC_skb_store_bytes = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_FUNC_skb_store_bytes"
    )
    BPF_FUNC_skb_store_bytes,

    /**
     * {@code BPF_FUNC_l3_csum_replace = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_FUNC_l3_csum_replace"
    )
    BPF_FUNC_l3_csum_replace,

    /**
     * {@code BPF_FUNC_l4_csum_replace = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_FUNC_l4_csum_replace"
    )
    BPF_FUNC_l4_csum_replace,

    /**
     * {@code BPF_FUNC_tail_call = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_FUNC_tail_call"
    )
    BPF_FUNC_tail_call,

    /**
     * {@code BPF_FUNC_clone_redirect = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_FUNC_clone_redirect"
    )
    BPF_FUNC_clone_redirect,

    /**
     * {@code BPF_FUNC_get_current_pid_tgid = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_FUNC_get_current_pid_tgid"
    )
    BPF_FUNC_get_current_pid_tgid,

    /**
     * {@code BPF_FUNC_get_current_uid_gid = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BPF_FUNC_get_current_uid_gid"
    )
    BPF_FUNC_get_current_uid_gid,

    /**
     * {@code BPF_FUNC_get_current_comm = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_FUNC_get_current_comm"
    )
    BPF_FUNC_get_current_comm,

    /**
     * {@code BPF_FUNC_get_cgroup_classid = 17}
     */
    @EnumMember(
        value = 17L,
        name = "BPF_FUNC_get_cgroup_classid"
    )
    BPF_FUNC_get_cgroup_classid,

    /**
     * {@code BPF_FUNC_skb_vlan_push = 18}
     */
    @EnumMember(
        value = 18L,
        name = "BPF_FUNC_skb_vlan_push"
    )
    BPF_FUNC_skb_vlan_push,

    /**
     * {@code BPF_FUNC_skb_vlan_pop = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_FUNC_skb_vlan_pop"
    )
    BPF_FUNC_skb_vlan_pop,

    /**
     * {@code BPF_FUNC_skb_get_tunnel_key = 20}
     */
    @EnumMember(
        value = 20L,
        name = "BPF_FUNC_skb_get_tunnel_key"
    )
    BPF_FUNC_skb_get_tunnel_key,

    /**
     * {@code BPF_FUNC_skb_set_tunnel_key = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_FUNC_skb_set_tunnel_key"
    )
    BPF_FUNC_skb_set_tunnel_key,

    /**
     * {@code BPF_FUNC_perf_event_read = 22}
     */
    @EnumMember(
        value = 22L,
        name = "BPF_FUNC_perf_event_read"
    )
    BPF_FUNC_perf_event_read,

    /**
     * {@code BPF_FUNC_redirect = 23}
     */
    @EnumMember(
        value = 23L,
        name = "BPF_FUNC_redirect"
    )
    BPF_FUNC_redirect,

    /**
     * {@code BPF_FUNC_get_route_realm = 24}
     */
    @EnumMember(
        value = 24L,
        name = "BPF_FUNC_get_route_realm"
    )
    BPF_FUNC_get_route_realm,

    /**
     * {@code BPF_FUNC_perf_event_output = 25}
     */
    @EnumMember(
        value = 25L,
        name = "BPF_FUNC_perf_event_output"
    )
    BPF_FUNC_perf_event_output,

    /**
     * {@code BPF_FUNC_skb_load_bytes = 26}
     */
    @EnumMember(
        value = 26L,
        name = "BPF_FUNC_skb_load_bytes"
    )
    BPF_FUNC_skb_load_bytes,

    /**
     * {@code BPF_FUNC_get_stackid = 27}
     */
    @EnumMember(
        value = 27L,
        name = "BPF_FUNC_get_stackid"
    )
    BPF_FUNC_get_stackid,

    /**
     * {@code BPF_FUNC_csum_diff = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_FUNC_csum_diff"
    )
    BPF_FUNC_csum_diff,

    /**
     * {@code BPF_FUNC_skb_get_tunnel_opt = 29}
     */
    @EnumMember(
        value = 29L,
        name = "BPF_FUNC_skb_get_tunnel_opt"
    )
    BPF_FUNC_skb_get_tunnel_opt,

    /**
     * {@code BPF_FUNC_skb_set_tunnel_opt = 30}
     */
    @EnumMember(
        value = 30L,
        name = "BPF_FUNC_skb_set_tunnel_opt"
    )
    BPF_FUNC_skb_set_tunnel_opt,

    /**
     * {@code BPF_FUNC_skb_change_proto = 31}
     */
    @EnumMember(
        value = 31L,
        name = "BPF_FUNC_skb_change_proto"
    )
    BPF_FUNC_skb_change_proto,

    /**
     * {@code BPF_FUNC_skb_change_type = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_FUNC_skb_change_type"
    )
    BPF_FUNC_skb_change_type,

    /**
     * {@code BPF_FUNC_skb_under_cgroup = 33}
     */
    @EnumMember(
        value = 33L,
        name = "BPF_FUNC_skb_under_cgroup"
    )
    BPF_FUNC_skb_under_cgroup,

    /**
     * {@code BPF_FUNC_get_hash_recalc = 34}
     */
    @EnumMember(
        value = 34L,
        name = "BPF_FUNC_get_hash_recalc"
    )
    BPF_FUNC_get_hash_recalc,

    /**
     * {@code BPF_FUNC_get_current_task = 35}
     */
    @EnumMember(
        value = 35L,
        name = "BPF_FUNC_get_current_task"
    )
    BPF_FUNC_get_current_task,

    /**
     * {@code BPF_FUNC_probe_write_user = 36}
     */
    @EnumMember(
        value = 36L,
        name = "BPF_FUNC_probe_write_user"
    )
    BPF_FUNC_probe_write_user,

    /**
     * {@code BPF_FUNC_current_task_under_cgroup = 37}
     */
    @EnumMember(
        value = 37L,
        name = "BPF_FUNC_current_task_under_cgroup"
    )
    BPF_FUNC_current_task_under_cgroup,

    /**
     * {@code BPF_FUNC_skb_change_tail = 38}
     */
    @EnumMember(
        value = 38L,
        name = "BPF_FUNC_skb_change_tail"
    )
    BPF_FUNC_skb_change_tail,

    /**
     * {@code BPF_FUNC_skb_pull_data = 39}
     */
    @EnumMember(
        value = 39L,
        name = "BPF_FUNC_skb_pull_data"
    )
    BPF_FUNC_skb_pull_data,

    /**
     * {@code BPF_FUNC_csum_update = 40}
     */
    @EnumMember(
        value = 40L,
        name = "BPF_FUNC_csum_update"
    )
    BPF_FUNC_csum_update,

    /**
     * {@code BPF_FUNC_set_hash_invalid = 41}
     */
    @EnumMember(
        value = 41L,
        name = "BPF_FUNC_set_hash_invalid"
    )
    BPF_FUNC_set_hash_invalid,

    /**
     * {@code BPF_FUNC_get_numa_node_id = 42}
     */
    @EnumMember(
        value = 42L,
        name = "BPF_FUNC_get_numa_node_id"
    )
    BPF_FUNC_get_numa_node_id,

    /**
     * {@code BPF_FUNC_skb_change_head = 43}
     */
    @EnumMember(
        value = 43L,
        name = "BPF_FUNC_skb_change_head"
    )
    BPF_FUNC_skb_change_head,

    /**
     * {@code BPF_FUNC_xdp_adjust_head = 44}
     */
    @EnumMember(
        value = 44L,
        name = "BPF_FUNC_xdp_adjust_head"
    )
    BPF_FUNC_xdp_adjust_head,

    /**
     * {@code BPF_FUNC_probe_read_str = 45}
     */
    @EnumMember(
        value = 45L,
        name = "BPF_FUNC_probe_read_str"
    )
    BPF_FUNC_probe_read_str,

    /**
     * {@code BPF_FUNC_get_socket_cookie = 46}
     */
    @EnumMember(
        value = 46L,
        name = "BPF_FUNC_get_socket_cookie"
    )
    BPF_FUNC_get_socket_cookie,

    /**
     * {@code BPF_FUNC_get_socket_uid = 47}
     */
    @EnumMember(
        value = 47L,
        name = "BPF_FUNC_get_socket_uid"
    )
    BPF_FUNC_get_socket_uid,

    /**
     * {@code BPF_FUNC_set_hash = 48}
     */
    @EnumMember(
        value = 48L,
        name = "BPF_FUNC_set_hash"
    )
    BPF_FUNC_set_hash,

    /**
     * {@code BPF_FUNC_setsockopt = 49}
     */
    @EnumMember(
        value = 49L,
        name = "BPF_FUNC_setsockopt"
    )
    BPF_FUNC_setsockopt,

    /**
     * {@code BPF_FUNC_skb_adjust_room = 50}
     */
    @EnumMember(
        value = 50L,
        name = "BPF_FUNC_skb_adjust_room"
    )
    BPF_FUNC_skb_adjust_room,

    /**
     * {@code BPF_FUNC_redirect_map = 51}
     */
    @EnumMember(
        value = 51L,
        name = "BPF_FUNC_redirect_map"
    )
    BPF_FUNC_redirect_map,

    /**
     * {@code BPF_FUNC_sk_redirect_map = 52}
     */
    @EnumMember(
        value = 52L,
        name = "BPF_FUNC_sk_redirect_map"
    )
    BPF_FUNC_sk_redirect_map,

    /**
     * {@code BPF_FUNC_sock_map_update = 53}
     */
    @EnumMember(
        value = 53L,
        name = "BPF_FUNC_sock_map_update"
    )
    BPF_FUNC_sock_map_update,

    /**
     * {@code BPF_FUNC_xdp_adjust_meta = 54}
     */
    @EnumMember(
        value = 54L,
        name = "BPF_FUNC_xdp_adjust_meta"
    )
    BPF_FUNC_xdp_adjust_meta,

    /**
     * {@code BPF_FUNC_perf_event_read_value = 55}
     */
    @EnumMember(
        value = 55L,
        name = "BPF_FUNC_perf_event_read_value"
    )
    BPF_FUNC_perf_event_read_value,

    /**
     * {@code BPF_FUNC_perf_prog_read_value = 56}
     */
    @EnumMember(
        value = 56L,
        name = "BPF_FUNC_perf_prog_read_value"
    )
    BPF_FUNC_perf_prog_read_value,

    /**
     * {@code BPF_FUNC_getsockopt = 57}
     */
    @EnumMember(
        value = 57L,
        name = "BPF_FUNC_getsockopt"
    )
    BPF_FUNC_getsockopt,

    /**
     * {@code BPF_FUNC_override_return = 58}
     */
    @EnumMember(
        value = 58L,
        name = "BPF_FUNC_override_return"
    )
    BPF_FUNC_override_return,

    /**
     * {@code BPF_FUNC_sock_ops_cb_flags_set = 59}
     */
    @EnumMember(
        value = 59L,
        name = "BPF_FUNC_sock_ops_cb_flags_set"
    )
    BPF_FUNC_sock_ops_cb_flags_set,

    /**
     * {@code BPF_FUNC_msg_redirect_map = 60}
     */
    @EnumMember(
        value = 60L,
        name = "BPF_FUNC_msg_redirect_map"
    )
    BPF_FUNC_msg_redirect_map,

    /**
     * {@code BPF_FUNC_msg_apply_bytes = 61}
     */
    @EnumMember(
        value = 61L,
        name = "BPF_FUNC_msg_apply_bytes"
    )
    BPF_FUNC_msg_apply_bytes,

    /**
     * {@code BPF_FUNC_msg_cork_bytes = 62}
     */
    @EnumMember(
        value = 62L,
        name = "BPF_FUNC_msg_cork_bytes"
    )
    BPF_FUNC_msg_cork_bytes,

    /**
     * {@code BPF_FUNC_msg_pull_data = 63}
     */
    @EnumMember(
        value = 63L,
        name = "BPF_FUNC_msg_pull_data"
    )
    BPF_FUNC_msg_pull_data,

    /**
     * {@code BPF_FUNC_bind = 64}
     */
    @EnumMember(
        value = 64L,
        name = "BPF_FUNC_bind"
    )
    BPF_FUNC_bind,

    /**
     * {@code BPF_FUNC_xdp_adjust_tail = 65}
     */
    @EnumMember(
        value = 65L,
        name = "BPF_FUNC_xdp_adjust_tail"
    )
    BPF_FUNC_xdp_adjust_tail,

    /**
     * {@code BPF_FUNC_skb_get_xfrm_state = 66}
     */
    @EnumMember(
        value = 66L,
        name = "BPF_FUNC_skb_get_xfrm_state"
    )
    BPF_FUNC_skb_get_xfrm_state,

    /**
     * {@code BPF_FUNC_get_stack = 67}
     */
    @EnumMember(
        value = 67L,
        name = "BPF_FUNC_get_stack"
    )
    BPF_FUNC_get_stack,

    /**
     * {@code BPF_FUNC_skb_load_bytes_relative = 68}
     */
    @EnumMember(
        value = 68L,
        name = "BPF_FUNC_skb_load_bytes_relative"
    )
    BPF_FUNC_skb_load_bytes_relative,

    /**
     * {@code BPF_FUNC_fib_lookup = 69}
     */
    @EnumMember(
        value = 69L,
        name = "BPF_FUNC_fib_lookup"
    )
    BPF_FUNC_fib_lookup,

    /**
     * {@code BPF_FUNC_sock_hash_update = 70}
     */
    @EnumMember(
        value = 70L,
        name = "BPF_FUNC_sock_hash_update"
    )
    BPF_FUNC_sock_hash_update,

    /**
     * {@code BPF_FUNC_msg_redirect_hash = 71}
     */
    @EnumMember(
        value = 71L,
        name = "BPF_FUNC_msg_redirect_hash"
    )
    BPF_FUNC_msg_redirect_hash,

    /**
     * {@code BPF_FUNC_sk_redirect_hash = 72}
     */
    @EnumMember(
        value = 72L,
        name = "BPF_FUNC_sk_redirect_hash"
    )
    BPF_FUNC_sk_redirect_hash,

    /**
     * {@code BPF_FUNC_lwt_push_encap = 73}
     */
    @EnumMember(
        value = 73L,
        name = "BPF_FUNC_lwt_push_encap"
    )
    BPF_FUNC_lwt_push_encap,

    /**
     * {@code BPF_FUNC_lwt_seg6_store_bytes = 74}
     */
    @EnumMember(
        value = 74L,
        name = "BPF_FUNC_lwt_seg6_store_bytes"
    )
    BPF_FUNC_lwt_seg6_store_bytes,

    /**
     * {@code BPF_FUNC_lwt_seg6_adjust_srh = 75}
     */
    @EnumMember(
        value = 75L,
        name = "BPF_FUNC_lwt_seg6_adjust_srh"
    )
    BPF_FUNC_lwt_seg6_adjust_srh,

    /**
     * {@code BPF_FUNC_lwt_seg6_action = 76}
     */
    @EnumMember(
        value = 76L,
        name = "BPF_FUNC_lwt_seg6_action"
    )
    BPF_FUNC_lwt_seg6_action,

    /**
     * {@code BPF_FUNC_rc_repeat = 77}
     */
    @EnumMember(
        value = 77L,
        name = "BPF_FUNC_rc_repeat"
    )
    BPF_FUNC_rc_repeat,

    /**
     * {@code BPF_FUNC_rc_keydown = 78}
     */
    @EnumMember(
        value = 78L,
        name = "BPF_FUNC_rc_keydown"
    )
    BPF_FUNC_rc_keydown,

    /**
     * {@code BPF_FUNC_skb_cgroup_id = 79}
     */
    @EnumMember(
        value = 79L,
        name = "BPF_FUNC_skb_cgroup_id"
    )
    BPF_FUNC_skb_cgroup_id,

    /**
     * {@code BPF_FUNC_get_current_cgroup_id = 80}
     */
    @EnumMember(
        value = 80L,
        name = "BPF_FUNC_get_current_cgroup_id"
    )
    BPF_FUNC_get_current_cgroup_id,

    /**
     * {@code BPF_FUNC_get_local_storage = 81}
     */
    @EnumMember(
        value = 81L,
        name = "BPF_FUNC_get_local_storage"
    )
    BPF_FUNC_get_local_storage,

    /**
     * {@code BPF_FUNC_sk_select_reuseport = 82}
     */
    @EnumMember(
        value = 82L,
        name = "BPF_FUNC_sk_select_reuseport"
    )
    BPF_FUNC_sk_select_reuseport,

    /**
     * {@code BPF_FUNC_skb_ancestor_cgroup_id = 83}
     */
    @EnumMember(
        value = 83L,
        name = "BPF_FUNC_skb_ancestor_cgroup_id"
    )
    BPF_FUNC_skb_ancestor_cgroup_id,

    /**
     * {@code BPF_FUNC_sk_lookup_tcp = 84}
     */
    @EnumMember(
        value = 84L,
        name = "BPF_FUNC_sk_lookup_tcp"
    )
    BPF_FUNC_sk_lookup_tcp,

    /**
     * {@code BPF_FUNC_sk_lookup_udp = 85}
     */
    @EnumMember(
        value = 85L,
        name = "BPF_FUNC_sk_lookup_udp"
    )
    BPF_FUNC_sk_lookup_udp,

    /**
     * {@code BPF_FUNC_sk_release = 86}
     */
    @EnumMember(
        value = 86L,
        name = "BPF_FUNC_sk_release"
    )
    BPF_FUNC_sk_release,

    /**
     * {@code BPF_FUNC_map_push_elem = 87}
     */
    @EnumMember(
        value = 87L,
        name = "BPF_FUNC_map_push_elem"
    )
    BPF_FUNC_map_push_elem,

    /**
     * {@code BPF_FUNC_map_pop_elem = 88}
     */
    @EnumMember(
        value = 88L,
        name = "BPF_FUNC_map_pop_elem"
    )
    BPF_FUNC_map_pop_elem,

    /**
     * {@code BPF_FUNC_map_peek_elem = 89}
     */
    @EnumMember(
        value = 89L,
        name = "BPF_FUNC_map_peek_elem"
    )
    BPF_FUNC_map_peek_elem,

    /**
     * {@code BPF_FUNC_msg_push_data = 90}
     */
    @EnumMember(
        value = 90L,
        name = "BPF_FUNC_msg_push_data"
    )
    BPF_FUNC_msg_push_data,

    /**
     * {@code BPF_FUNC_msg_pop_data = 91}
     */
    @EnumMember(
        value = 91L,
        name = "BPF_FUNC_msg_pop_data"
    )
    BPF_FUNC_msg_pop_data,

    /**
     * {@code BPF_FUNC_rc_pointer_rel = 92}
     */
    @EnumMember(
        value = 92L,
        name = "BPF_FUNC_rc_pointer_rel"
    )
    BPF_FUNC_rc_pointer_rel,

    /**
     * {@code BPF_FUNC_spin_lock = 93}
     */
    @EnumMember(
        value = 93L,
        name = "BPF_FUNC_spin_lock"
    )
    BPF_FUNC_spin_lock,

    /**
     * {@code BPF_FUNC_spin_unlock = 94}
     */
    @EnumMember(
        value = 94L,
        name = "BPF_FUNC_spin_unlock"
    )
    BPF_FUNC_spin_unlock,

    /**
     * {@code BPF_FUNC_sk_fullsock = 95}
     */
    @EnumMember(
        value = 95L,
        name = "BPF_FUNC_sk_fullsock"
    )
    BPF_FUNC_sk_fullsock,

    /**
     * {@code BPF_FUNC_tcp_sock = 96}
     */
    @EnumMember(
        value = 96L,
        name = "BPF_FUNC_tcp_sock"
    )
    BPF_FUNC_tcp_sock,

    /**
     * {@code BPF_FUNC_skb_ecn_set_ce = 97}
     */
    @EnumMember(
        value = 97L,
        name = "BPF_FUNC_skb_ecn_set_ce"
    )
    BPF_FUNC_skb_ecn_set_ce,

    /**
     * {@code BPF_FUNC_get_listener_sock = 98}
     */
    @EnumMember(
        value = 98L,
        name = "BPF_FUNC_get_listener_sock"
    )
    BPF_FUNC_get_listener_sock,

    /**
     * {@code BPF_FUNC_skc_lookup_tcp = 99}
     */
    @EnumMember(
        value = 99L,
        name = "BPF_FUNC_skc_lookup_tcp"
    )
    BPF_FUNC_skc_lookup_tcp,

    /**
     * {@code BPF_FUNC_tcp_check_syncookie = 100}
     */
    @EnumMember(
        value = 100L,
        name = "BPF_FUNC_tcp_check_syncookie"
    )
    BPF_FUNC_tcp_check_syncookie,

    /**
     * {@code BPF_FUNC_sysctl_get_name = 101}
     */
    @EnumMember(
        value = 101L,
        name = "BPF_FUNC_sysctl_get_name"
    )
    BPF_FUNC_sysctl_get_name,

    /**
     * {@code BPF_FUNC_sysctl_get_current_value = 102}
     */
    @EnumMember(
        value = 102L,
        name = "BPF_FUNC_sysctl_get_current_value"
    )
    BPF_FUNC_sysctl_get_current_value,

    /**
     * {@code BPF_FUNC_sysctl_get_new_value = 103}
     */
    @EnumMember(
        value = 103L,
        name = "BPF_FUNC_sysctl_get_new_value"
    )
    BPF_FUNC_sysctl_get_new_value,

    /**
     * {@code BPF_FUNC_sysctl_set_new_value = 104}
     */
    @EnumMember(
        value = 104L,
        name = "BPF_FUNC_sysctl_set_new_value"
    )
    BPF_FUNC_sysctl_set_new_value,

    /**
     * {@code BPF_FUNC_strtol = 105}
     */
    @EnumMember(
        value = 105L,
        name = "BPF_FUNC_strtol"
    )
    BPF_FUNC_strtol,

    /**
     * {@code BPF_FUNC_strtoul = 106}
     */
    @EnumMember(
        value = 106L,
        name = "BPF_FUNC_strtoul"
    )
    BPF_FUNC_strtoul,

    /**
     * {@code BPF_FUNC_sk_storage_get = 107}
     */
    @EnumMember(
        value = 107L,
        name = "BPF_FUNC_sk_storage_get"
    )
    BPF_FUNC_sk_storage_get,

    /**
     * {@code BPF_FUNC_sk_storage_delete = 108}
     */
    @EnumMember(
        value = 108L,
        name = "BPF_FUNC_sk_storage_delete"
    )
    BPF_FUNC_sk_storage_delete,

    /**
     * {@code BPF_FUNC_send_signal = 109}
     */
    @EnumMember(
        value = 109L,
        name = "BPF_FUNC_send_signal"
    )
    BPF_FUNC_send_signal,

    /**
     * {@code BPF_FUNC_tcp_gen_syncookie = 110}
     */
    @EnumMember(
        value = 110L,
        name = "BPF_FUNC_tcp_gen_syncookie"
    )
    BPF_FUNC_tcp_gen_syncookie,

    /**
     * {@code BPF_FUNC_skb_output = 111}
     */
    @EnumMember(
        value = 111L,
        name = "BPF_FUNC_skb_output"
    )
    BPF_FUNC_skb_output,

    /**
     * {@code BPF_FUNC_probe_read_user = 112}
     */
    @EnumMember(
        value = 112L,
        name = "BPF_FUNC_probe_read_user"
    )
    BPF_FUNC_probe_read_user,

    /**
     * {@code BPF_FUNC_probe_read_kernel = 113}
     */
    @EnumMember(
        value = 113L,
        name = "BPF_FUNC_probe_read_kernel"
    )
    BPF_FUNC_probe_read_kernel,

    /**
     * {@code BPF_FUNC_probe_read_user_str = 114}
     */
    @EnumMember(
        value = 114L,
        name = "BPF_FUNC_probe_read_user_str"
    )
    BPF_FUNC_probe_read_user_str,

    /**
     * {@code BPF_FUNC_probe_read_kernel_str = 115}
     */
    @EnumMember(
        value = 115L,
        name = "BPF_FUNC_probe_read_kernel_str"
    )
    BPF_FUNC_probe_read_kernel_str,

    /**
     * {@code BPF_FUNC_tcp_send_ack = 116}
     */
    @EnumMember(
        value = 116L,
        name = "BPF_FUNC_tcp_send_ack"
    )
    BPF_FUNC_tcp_send_ack,

    /**
     * {@code BPF_FUNC_send_signal_thread = 117}
     */
    @EnumMember(
        value = 117L,
        name = "BPF_FUNC_send_signal_thread"
    )
    BPF_FUNC_send_signal_thread,

    /**
     * {@code BPF_FUNC_jiffies64 = 118}
     */
    @EnumMember(
        value = 118L,
        name = "BPF_FUNC_jiffies64"
    )
    BPF_FUNC_jiffies64,

    /**
     * {@code BPF_FUNC_read_branch_records = 119}
     */
    @EnumMember(
        value = 119L,
        name = "BPF_FUNC_read_branch_records"
    )
    BPF_FUNC_read_branch_records,

    /**
     * {@code BPF_FUNC_get_ns_current_pid_tgid = 120}
     */
    @EnumMember(
        value = 120L,
        name = "BPF_FUNC_get_ns_current_pid_tgid"
    )
    BPF_FUNC_get_ns_current_pid_tgid,

    /**
     * {@code BPF_FUNC_xdp_output = 121}
     */
    @EnumMember(
        value = 121L,
        name = "BPF_FUNC_xdp_output"
    )
    BPF_FUNC_xdp_output,

    /**
     * {@code BPF_FUNC_get_netns_cookie = 122}
     */
    @EnumMember(
        value = 122L,
        name = "BPF_FUNC_get_netns_cookie"
    )
    BPF_FUNC_get_netns_cookie,

    /**
     * {@code BPF_FUNC_get_current_ancestor_cgroup_id = 123}
     */
    @EnumMember(
        value = 123L,
        name = "BPF_FUNC_get_current_ancestor_cgroup_id"
    )
    BPF_FUNC_get_current_ancestor_cgroup_id,

    /**
     * {@code BPF_FUNC_sk_assign = 124}
     */
    @EnumMember(
        value = 124L,
        name = "BPF_FUNC_sk_assign"
    )
    BPF_FUNC_sk_assign,

    /**
     * {@code BPF_FUNC_ktime_get_boot_ns = 125}
     */
    @EnumMember(
        value = 125L,
        name = "BPF_FUNC_ktime_get_boot_ns"
    )
    BPF_FUNC_ktime_get_boot_ns,

    /**
     * {@code BPF_FUNC_seq_printf = 126}
     */
    @EnumMember(
        value = 126L,
        name = "BPF_FUNC_seq_printf"
    )
    BPF_FUNC_seq_printf,

    /**
     * {@code BPF_FUNC_seq_write = 127}
     */
    @EnumMember(
        value = 127L,
        name = "BPF_FUNC_seq_write"
    )
    BPF_FUNC_seq_write,

    /**
     * {@code BPF_FUNC_sk_cgroup_id = 128}
     */
    @EnumMember(
        value = 128L,
        name = "BPF_FUNC_sk_cgroup_id"
    )
    BPF_FUNC_sk_cgroup_id,

    /**
     * {@code BPF_FUNC_sk_ancestor_cgroup_id = 129}
     */
    @EnumMember(
        value = 129L,
        name = "BPF_FUNC_sk_ancestor_cgroup_id"
    )
    BPF_FUNC_sk_ancestor_cgroup_id,

    /**
     * {@code BPF_FUNC_ringbuf_output = 130}
     */
    @EnumMember(
        value = 130L,
        name = "BPF_FUNC_ringbuf_output"
    )
    BPF_FUNC_ringbuf_output,

    /**
     * {@code BPF_FUNC_ringbuf_reserve = 131}
     */
    @EnumMember(
        value = 131L,
        name = "BPF_FUNC_ringbuf_reserve"
    )
    BPF_FUNC_ringbuf_reserve,

    /**
     * {@code BPF_FUNC_ringbuf_submit = 132}
     */
    @EnumMember(
        value = 132L,
        name = "BPF_FUNC_ringbuf_submit"
    )
    BPF_FUNC_ringbuf_submit,

    /**
     * {@code BPF_FUNC_ringbuf_discard = 133}
     */
    @EnumMember(
        value = 133L,
        name = "BPF_FUNC_ringbuf_discard"
    )
    BPF_FUNC_ringbuf_discard,

    /**
     * {@code BPF_FUNC_ringbuf_query = 134}
     */
    @EnumMember(
        value = 134L,
        name = "BPF_FUNC_ringbuf_query"
    )
    BPF_FUNC_ringbuf_query,

    /**
     * {@code BPF_FUNC_csum_level = 135}
     */
    @EnumMember(
        value = 135L,
        name = "BPF_FUNC_csum_level"
    )
    BPF_FUNC_csum_level,

    /**
     * {@code BPF_FUNC_skc_to_tcp6_sock = 136}
     */
    @EnumMember(
        value = 136L,
        name = "BPF_FUNC_skc_to_tcp6_sock"
    )
    BPF_FUNC_skc_to_tcp6_sock,

    /**
     * {@code BPF_FUNC_skc_to_tcp_sock = 137}
     */
    @EnumMember(
        value = 137L,
        name = "BPF_FUNC_skc_to_tcp_sock"
    )
    BPF_FUNC_skc_to_tcp_sock,

    /**
     * {@code BPF_FUNC_skc_to_tcp_timewait_sock = 138}
     */
    @EnumMember(
        value = 138L,
        name = "BPF_FUNC_skc_to_tcp_timewait_sock"
    )
    BPF_FUNC_skc_to_tcp_timewait_sock,

    /**
     * {@code BPF_FUNC_skc_to_tcp_request_sock = 139}
     */
    @EnumMember(
        value = 139L,
        name = "BPF_FUNC_skc_to_tcp_request_sock"
    )
    BPF_FUNC_skc_to_tcp_request_sock,

    /**
     * {@code BPF_FUNC_skc_to_udp6_sock = 140}
     */
    @EnumMember(
        value = 140L,
        name = "BPF_FUNC_skc_to_udp6_sock"
    )
    BPF_FUNC_skc_to_udp6_sock,

    /**
     * {@code BPF_FUNC_get_task_stack = 141}
     */
    @EnumMember(
        value = 141L,
        name = "BPF_FUNC_get_task_stack"
    )
    BPF_FUNC_get_task_stack,

    /**
     * {@code BPF_FUNC_load_hdr_opt = 142}
     */
    @EnumMember(
        value = 142L,
        name = "BPF_FUNC_load_hdr_opt"
    )
    BPF_FUNC_load_hdr_opt,

    /**
     * {@code BPF_FUNC_store_hdr_opt = 143}
     */
    @EnumMember(
        value = 143L,
        name = "BPF_FUNC_store_hdr_opt"
    )
    BPF_FUNC_store_hdr_opt,

    /**
     * {@code BPF_FUNC_reserve_hdr_opt = 144}
     */
    @EnumMember(
        value = 144L,
        name = "BPF_FUNC_reserve_hdr_opt"
    )
    BPF_FUNC_reserve_hdr_opt,

    /**
     * {@code BPF_FUNC_inode_storage_get = 145}
     */
    @EnumMember(
        value = 145L,
        name = "BPF_FUNC_inode_storage_get"
    )
    BPF_FUNC_inode_storage_get,

    /**
     * {@code BPF_FUNC_inode_storage_delete = 146}
     */
    @EnumMember(
        value = 146L,
        name = "BPF_FUNC_inode_storage_delete"
    )
    BPF_FUNC_inode_storage_delete,

    /**
     * {@code BPF_FUNC_d_path = 147}
     */
    @EnumMember(
        value = 147L,
        name = "BPF_FUNC_d_path"
    )
    BPF_FUNC_d_path,

    /**
     * {@code BPF_FUNC_copy_from_user = 148}
     */
    @EnumMember(
        value = 148L,
        name = "BPF_FUNC_copy_from_user"
    )
    BPF_FUNC_copy_from_user,

    /**
     * {@code BPF_FUNC_snprintf_btf = 149}
     */
    @EnumMember(
        value = 149L,
        name = "BPF_FUNC_snprintf_btf"
    )
    BPF_FUNC_snprintf_btf,

    /**
     * {@code BPF_FUNC_seq_printf_btf = 150}
     */
    @EnumMember(
        value = 150L,
        name = "BPF_FUNC_seq_printf_btf"
    )
    BPF_FUNC_seq_printf_btf,

    /**
     * {@code BPF_FUNC_skb_cgroup_classid = 151}
     */
    @EnumMember(
        value = 151L,
        name = "BPF_FUNC_skb_cgroup_classid"
    )
    BPF_FUNC_skb_cgroup_classid,

    /**
     * {@code BPF_FUNC_redirect_neigh = 152}
     */
    @EnumMember(
        value = 152L,
        name = "BPF_FUNC_redirect_neigh"
    )
    BPF_FUNC_redirect_neigh,

    /**
     * {@code BPF_FUNC_per_cpu_ptr = 153}
     */
    @EnumMember(
        value = 153L,
        name = "BPF_FUNC_per_cpu_ptr"
    )
    BPF_FUNC_per_cpu_ptr,

    /**
     * {@code BPF_FUNC_this_cpu_ptr = 154}
     */
    @EnumMember(
        value = 154L,
        name = "BPF_FUNC_this_cpu_ptr"
    )
    BPF_FUNC_this_cpu_ptr,

    /**
     * {@code BPF_FUNC_redirect_peer = 155}
     */
    @EnumMember(
        value = 155L,
        name = "BPF_FUNC_redirect_peer"
    )
    BPF_FUNC_redirect_peer,

    /**
     * {@code BPF_FUNC_task_storage_get = 156}
     */
    @EnumMember(
        value = 156L,
        name = "BPF_FUNC_task_storage_get"
    )
    BPF_FUNC_task_storage_get,

    /**
     * {@code BPF_FUNC_task_storage_delete = 157}
     */
    @EnumMember(
        value = 157L,
        name = "BPF_FUNC_task_storage_delete"
    )
    BPF_FUNC_task_storage_delete,

    /**
     * {@code BPF_FUNC_get_current_task_btf = 158}
     */
    @EnumMember(
        value = 158L,
        name = "BPF_FUNC_get_current_task_btf"
    )
    BPF_FUNC_get_current_task_btf,

    /**
     * {@code BPF_FUNC_bprm_opts_set = 159}
     */
    @EnumMember(
        value = 159L,
        name = "BPF_FUNC_bprm_opts_set"
    )
    BPF_FUNC_bprm_opts_set,

    /**
     * {@code BPF_FUNC_ktime_get_coarse_ns = 160}
     */
    @EnumMember(
        value = 160L,
        name = "BPF_FUNC_ktime_get_coarse_ns"
    )
    BPF_FUNC_ktime_get_coarse_ns,

    /**
     * {@code BPF_FUNC_ima_inode_hash = 161}
     */
    @EnumMember(
        value = 161L,
        name = "BPF_FUNC_ima_inode_hash"
    )
    BPF_FUNC_ima_inode_hash,

    /**
     * {@code BPF_FUNC_sock_from_file = 162}
     */
    @EnumMember(
        value = 162L,
        name = "BPF_FUNC_sock_from_file"
    )
    BPF_FUNC_sock_from_file,

    /**
     * {@code BPF_FUNC_check_mtu = 163}
     */
    @EnumMember(
        value = 163L,
        name = "BPF_FUNC_check_mtu"
    )
    BPF_FUNC_check_mtu,

    /**
     * {@code BPF_FUNC_for_each_map_elem = 164}
     */
    @EnumMember(
        value = 164L,
        name = "BPF_FUNC_for_each_map_elem"
    )
    BPF_FUNC_for_each_map_elem,

    /**
     * {@code BPF_FUNC_snprintf = 165}
     */
    @EnumMember(
        value = 165L,
        name = "BPF_FUNC_snprintf"
    )
    BPF_FUNC_snprintf,

    /**
     * {@code BPF_FUNC_sys_bpf = 166}
     */
    @EnumMember(
        value = 166L,
        name = "BPF_FUNC_sys_bpf"
    )
    BPF_FUNC_sys_bpf,

    /**
     * {@code BPF_FUNC_btf_find_by_name_kind = 167}
     */
    @EnumMember(
        value = 167L,
        name = "BPF_FUNC_btf_find_by_name_kind"
    )
    BPF_FUNC_btf_find_by_name_kind,

    /**
     * {@code BPF_FUNC_sys_close = 168}
     */
    @EnumMember(
        value = 168L,
        name = "BPF_FUNC_sys_close"
    )
    BPF_FUNC_sys_close,

    /**
     * {@code BPF_FUNC_timer_init = 169}
     */
    @EnumMember(
        value = 169L,
        name = "BPF_FUNC_timer_init"
    )
    BPF_FUNC_timer_init,

    /**
     * {@code BPF_FUNC_timer_set_callback = 170}
     */
    @EnumMember(
        value = 170L,
        name = "BPF_FUNC_timer_set_callback"
    )
    BPF_FUNC_timer_set_callback,

    /**
     * {@code BPF_FUNC_timer_start = 171}
     */
    @EnumMember(
        value = 171L,
        name = "BPF_FUNC_timer_start"
    )
    BPF_FUNC_timer_start,

    /**
     * {@code BPF_FUNC_timer_cancel = 172}
     */
    @EnumMember(
        value = 172L,
        name = "BPF_FUNC_timer_cancel"
    )
    BPF_FUNC_timer_cancel,

    /**
     * {@code BPF_FUNC_get_func_ip = 173}
     */
    @EnumMember(
        value = 173L,
        name = "BPF_FUNC_get_func_ip"
    )
    BPF_FUNC_get_func_ip,

    /**
     * {@code BPF_FUNC_get_attach_cookie = 174}
     */
    @EnumMember(
        value = 174L,
        name = "BPF_FUNC_get_attach_cookie"
    )
    BPF_FUNC_get_attach_cookie,

    /**
     * {@code BPF_FUNC_task_pt_regs = 175}
     */
    @EnumMember(
        value = 175L,
        name = "BPF_FUNC_task_pt_regs"
    )
    BPF_FUNC_task_pt_regs,

    /**
     * {@code BPF_FUNC_get_branch_snapshot = 176}
     */
    @EnumMember(
        value = 176L,
        name = "BPF_FUNC_get_branch_snapshot"
    )
    BPF_FUNC_get_branch_snapshot,

    /**
     * {@code BPF_FUNC_trace_vprintk = 177}
     */
    @EnumMember(
        value = 177L,
        name = "BPF_FUNC_trace_vprintk"
    )
    BPF_FUNC_trace_vprintk,

    /**
     * {@code BPF_FUNC_skc_to_unix_sock = 178}
     */
    @EnumMember(
        value = 178L,
        name = "BPF_FUNC_skc_to_unix_sock"
    )
    BPF_FUNC_skc_to_unix_sock,

    /**
     * {@code BPF_FUNC_kallsyms_lookup_name = 179}
     */
    @EnumMember(
        value = 179L,
        name = "BPF_FUNC_kallsyms_lookup_name"
    )
    BPF_FUNC_kallsyms_lookup_name,

    /**
     * {@code BPF_FUNC_find_vma = 180}
     */
    @EnumMember(
        value = 180L,
        name = "BPF_FUNC_find_vma"
    )
    BPF_FUNC_find_vma,

    /**
     * {@code BPF_FUNC_loop = 181}
     */
    @EnumMember(
        value = 181L,
        name = "BPF_FUNC_loop"
    )
    BPF_FUNC_loop,

    /**
     * {@code BPF_FUNC_strncmp = 182}
     */
    @EnumMember(
        value = 182L,
        name = "BPF_FUNC_strncmp"
    )
    BPF_FUNC_strncmp,

    /**
     * {@code BPF_FUNC_get_func_arg = 183}
     */
    @EnumMember(
        value = 183L,
        name = "BPF_FUNC_get_func_arg"
    )
    BPF_FUNC_get_func_arg,

    /**
     * {@code BPF_FUNC_get_func_ret = 184}
     */
    @EnumMember(
        value = 184L,
        name = "BPF_FUNC_get_func_ret"
    )
    BPF_FUNC_get_func_ret,

    /**
     * {@code BPF_FUNC_get_func_arg_cnt = 185}
     */
    @EnumMember(
        value = 185L,
        name = "BPF_FUNC_get_func_arg_cnt"
    )
    BPF_FUNC_get_func_arg_cnt,

    /**
     * {@code BPF_FUNC_get_retval = 186}
     */
    @EnumMember(
        value = 186L,
        name = "BPF_FUNC_get_retval"
    )
    BPF_FUNC_get_retval,

    /**
     * {@code BPF_FUNC_set_retval = 187}
     */
    @EnumMember(
        value = 187L,
        name = "BPF_FUNC_set_retval"
    )
    BPF_FUNC_set_retval,

    /**
     * {@code BPF_FUNC_xdp_get_buff_len = 188}
     */
    @EnumMember(
        value = 188L,
        name = "BPF_FUNC_xdp_get_buff_len"
    )
    BPF_FUNC_xdp_get_buff_len,

    /**
     * {@code BPF_FUNC_xdp_load_bytes = 189}
     */
    @EnumMember(
        value = 189L,
        name = "BPF_FUNC_xdp_load_bytes"
    )
    BPF_FUNC_xdp_load_bytes,

    /**
     * {@code BPF_FUNC_xdp_store_bytes = 190}
     */
    @EnumMember(
        value = 190L,
        name = "BPF_FUNC_xdp_store_bytes"
    )
    BPF_FUNC_xdp_store_bytes,

    /**
     * {@code BPF_FUNC_copy_from_user_task = 191}
     */
    @EnumMember(
        value = 191L,
        name = "BPF_FUNC_copy_from_user_task"
    )
    BPF_FUNC_copy_from_user_task,

    /**
     * {@code BPF_FUNC_skb_set_tstamp = 192}
     */
    @EnumMember(
        value = 192L,
        name = "BPF_FUNC_skb_set_tstamp"
    )
    BPF_FUNC_skb_set_tstamp,

    /**
     * {@code BPF_FUNC_ima_file_hash = 193}
     */
    @EnumMember(
        value = 193L,
        name = "BPF_FUNC_ima_file_hash"
    )
    BPF_FUNC_ima_file_hash,

    /**
     * {@code BPF_FUNC_kptr_xchg = 194}
     */
    @EnumMember(
        value = 194L,
        name = "BPF_FUNC_kptr_xchg"
    )
    BPF_FUNC_kptr_xchg,

    /**
     * {@code BPF_FUNC_map_lookup_percpu_elem = 195}
     */
    @EnumMember(
        value = 195L,
        name = "BPF_FUNC_map_lookup_percpu_elem"
    )
    BPF_FUNC_map_lookup_percpu_elem,

    /**
     * {@code BPF_FUNC_skc_to_mptcp_sock = 196}
     */
    @EnumMember(
        value = 196L,
        name = "BPF_FUNC_skc_to_mptcp_sock"
    )
    BPF_FUNC_skc_to_mptcp_sock,

    /**
     * {@code BPF_FUNC_dynptr_from_mem = 197}
     */
    @EnumMember(
        value = 197L,
        name = "BPF_FUNC_dynptr_from_mem"
    )
    BPF_FUNC_dynptr_from_mem,

    /**
     * {@code BPF_FUNC_ringbuf_reserve_dynptr = 198}
     */
    @EnumMember(
        value = 198L,
        name = "BPF_FUNC_ringbuf_reserve_dynptr"
    )
    BPF_FUNC_ringbuf_reserve_dynptr,

    /**
     * {@code BPF_FUNC_ringbuf_submit_dynptr = 199}
     */
    @EnumMember(
        value = 199L,
        name = "BPF_FUNC_ringbuf_submit_dynptr"
    )
    BPF_FUNC_ringbuf_submit_dynptr,

    /**
     * {@code BPF_FUNC_ringbuf_discard_dynptr = 200}
     */
    @EnumMember(
        value = 200L,
        name = "BPF_FUNC_ringbuf_discard_dynptr"
    )
    BPF_FUNC_ringbuf_discard_dynptr,

    /**
     * {@code BPF_FUNC_dynptr_read = 201}
     */
    @EnumMember(
        value = 201L,
        name = "BPF_FUNC_dynptr_read"
    )
    BPF_FUNC_dynptr_read,

    /**
     * {@code BPF_FUNC_dynptr_write = 202}
     */
    @EnumMember(
        value = 202L,
        name = "BPF_FUNC_dynptr_write"
    )
    BPF_FUNC_dynptr_write,

    /**
     * {@code BPF_FUNC_dynptr_data = 203}
     */
    @EnumMember(
        value = 203L,
        name = "BPF_FUNC_dynptr_data"
    )
    BPF_FUNC_dynptr_data,

    /**
     * {@code BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204}
     */
    @EnumMember(
        value = 204L,
        name = "BPF_FUNC_tcp_raw_gen_syncookie_ipv4"
    )
    BPF_FUNC_tcp_raw_gen_syncookie_ipv4,

    /**
     * {@code BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205}
     */
    @EnumMember(
        value = 205L,
        name = "BPF_FUNC_tcp_raw_gen_syncookie_ipv6"
    )
    BPF_FUNC_tcp_raw_gen_syncookie_ipv6,

    /**
     * {@code BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206}
     */
    @EnumMember(
        value = 206L,
        name = "BPF_FUNC_tcp_raw_check_syncookie_ipv4"
    )
    BPF_FUNC_tcp_raw_check_syncookie_ipv4,

    /**
     * {@code BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207}
     */
    @EnumMember(
        value = 207L,
        name = "BPF_FUNC_tcp_raw_check_syncookie_ipv6"
    )
    BPF_FUNC_tcp_raw_check_syncookie_ipv6,

    /**
     * {@code BPF_FUNC_ktime_get_tai_ns = 208}
     */
    @EnumMember(
        value = 208L,
        name = "BPF_FUNC_ktime_get_tai_ns"
    )
    BPF_FUNC_ktime_get_tai_ns,

    /**
     * {@code BPF_FUNC_user_ringbuf_drain = 209}
     */
    @EnumMember(
        value = 209L,
        name = "BPF_FUNC_user_ringbuf_drain"
    )
    BPF_FUNC_user_ringbuf_drain,

    /**
     * {@code BPF_FUNC_cgrp_storage_get = 210}
     */
    @EnumMember(
        value = 210L,
        name = "BPF_FUNC_cgrp_storage_get"
    )
    BPF_FUNC_cgrp_storage_get,

    /**
     * {@code BPF_FUNC_cgrp_storage_delete = 211}
     */
    @EnumMember(
        value = 211L,
        name = "BPF_FUNC_cgrp_storage_delete"
    )
    BPF_FUNC_cgrp_storage_delete,

    /**
     * {@code __BPF_FUNC_MAX_ID = 212}
     */
    @EnumMember(
        value = 212L,
        name = "__BPF_FUNC_MAX_ID"
    )
    __BPF_FUNC_MAX_ID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_link_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_link_info extends Struct {
    public @Unsigned int type;

    public @Unsigned int id;

    public @Unsigned int prog_id;

    @InlineUnion(2020)
    public raw_tracepoint_of_anon_member_of_bpf_link_info raw_tracepoint;

    @InlineUnion(2020)
    public tracing_of_anon_member_of_bpf_link_info tracing;

    @InlineUnion(2020)
    public cgroup_of_anon_member_of_bpf_link_info cgroup;

    @InlineUnion(2020)
    public iter_of_anon_member_of_bpf_link_info iter;

    @InlineUnion(2020)
    public netns_of_anon_member_of_bpf_link_info netns;

    @InlineUnion(2020)
    public xdp_of_anon_member_of_bpf_link_info xdp;

    @InlineUnion(2020)
    public map_of_anon_member_of_iter_of_anon_member_of_bpf_link_info_and_struct_ops_of_anon_member_of_bpf_link_info struct_ops;

    @InlineUnion(2020)
    public netfilter_of_anon_member_of_bpf_link_info_and_netfilter_of_anon_member_of_link_create_of_bpf_attr netfilter;

    @InlineUnion(2020)
    public kprobe_multi_of_anon_member_of_bpf_link_info kprobe_multi;

    @InlineUnion(2020)
    public uprobe_multi_of_anon_member_of_bpf_link_info uprobe_multi;

    @InlineUnion(2020)
    public perf_event_of_anon_member_of_bpf_link_info perf_event;

    @InlineUnion(2020)
    public netkit_of_anon_member_of_bpf_link_info_and_tcx_of_anon_member_of_bpf_link_info tcx;

    @InlineUnion(2020)
    public netkit_of_anon_member_of_bpf_link_info_and_tcx_of_anon_member_of_bpf_link_info netkit;

    @InlineUnion(2020)
    public sockmap_of_anon_member_of_bpf_link_info sockmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_func_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_func_info extends Struct {
    public @Unsigned int insn_off;

    public @Unsigned int type_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_line_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_line_info extends Struct {
    public @Unsigned int insn_off;

    public @Unsigned int file_name_off;

    public @Unsigned int line_off;

    public @Unsigned int line_col;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog extends Struct {
    public @Unsigned short pages;

    public @Unsigned short jited;

    public @Unsigned short jit_requested;

    public @Unsigned short gpl_compatible;

    public @Unsigned short cb_access;

    public @Unsigned short dst_needed;

    public @Unsigned short blinding_requested;

    public @Unsigned short blinded;

    public @Unsigned short is_func;

    public @Unsigned short kprobe_override;

    public @Unsigned short has_callchain_buf;

    public @Unsigned short enforce_expected_attach_type;

    public @Unsigned short call_get_stack;

    public @Unsigned short call_get_func_ip;

    public @Unsigned short tstamp_type_access;

    public @Unsigned short sleepable;

    public bpf_prog_type type;

    public bpf_attach_type expected_attach_type;

    public @Unsigned int len;

    public @Unsigned int jited_len;

    public char @Size(8) [] tag;

    public Ptr<bpf_prog_stats> stats;

    public Ptr<java.lang.Integer> active;

    public Ptr<?> bpf_func;

    public Ptr<bpf_prog_aux> aux;

    public Ptr<sock_fprog_kern> orig_prog;

    @InlineUnion(2301)
    public anon_member_of_anon_member_of_bpf_prog anon26$0;

    @InlineUnion(2301)
    public anon_member_of_anon_member_of_bpf_prog anon26$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_aux_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_aux_info extends Struct {
    public Ptr<bpf_map> map;

    public cgroup_of_bpf_iter_aux_info cgroup;

    public task_of_bpf_iter_aux_info task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_info extends Struct {
    public Ptr<seq_operations> seq_ops;

    public @OriginalName("bpf_iter_init_seq_priv_t") Ptr<?> init_seq_private;

    public @OriginalName("bpf_iter_fini_seq_priv_t") Ptr<?> fini_seq_private;

    public @Unsigned int seq_priv_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map_ops extends Struct {
    public Ptr<?> map_alloc_check;

    public Ptr<?> map_alloc;

    public Ptr<?> map_release;

    public Ptr<?> map_free;

    public Ptr<?> map_get_next_key;

    public Ptr<?> map_release_uref;

    public Ptr<?> map_lookup_elem_sys_only;

    public Ptr<?> map_lookup_batch;

    public Ptr<?> map_lookup_and_delete_elem;

    public Ptr<?> map_lookup_and_delete_batch;

    public Ptr<?> map_update_batch;

    public Ptr<?> map_delete_batch;

    public Ptr<?> map_lookup_elem;

    public Ptr<?> map_update_elem;

    public Ptr<?> map_delete_elem;

    public Ptr<?> map_push_elem;

    public Ptr<?> map_pop_elem;

    public Ptr<?> map_peek_elem;

    public Ptr<?> map_lookup_percpu_elem;

    public Ptr<?> map_fd_get_ptr;

    public Ptr<?> map_fd_put_ptr;

    public Ptr<?> map_gen_lookup;

    public Ptr<?> map_fd_sys_lookup_elem;

    public Ptr<?> map_seq_show_elem;

    public Ptr<?> map_check_btf;

    public Ptr<?> map_poke_track;

    public Ptr<?> map_poke_untrack;

    public Ptr<?> map_poke_run;

    public Ptr<?> map_direct_value_addr;

    public Ptr<?> map_direct_value_meta;

    public Ptr<?> map_mmap;

    public Ptr<?> map_poll;

    public Ptr<?> map_get_unmapped_area;

    public Ptr<?> map_local_storage_charge;

    public Ptr<?> map_local_storage_uncharge;

    public Ptr<?> map_owner_storage_ptr;

    public Ptr<?> map_redirect;

    public Ptr<?> map_meta_equal;

    public Ptr<?> map_set_for_each_callback_args;

    public Ptr<?> map_for_each_callback;

    public Ptr<?> map_mem_usage;

    public Ptr<java.lang.Integer> map_btf_id;

    public Ptr<bpf_iter_seq_info> iter_seq_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map extends Struct {
    public Ptr<bpf_map_ops> ops;

    public Ptr<bpf_map> inner_map_meta;

    public Ptr<?> security;

    public bpf_map_type map_type;

    public @Unsigned int key_size;

    public @Unsigned int value_size;

    public @Unsigned int max_entries;

    public @Unsigned long map_extra;

    public @Unsigned int map_flags;

    public @Unsigned int id;

    public Ptr<btf_record> record;

    public int numa_node;

    public @Unsigned int btf_key_type_id;

    public @Unsigned int btf_value_type_id;

    public @Unsigned int btf_vmlinux_value_type_id;

    public Ptr<btf> btf;

    public Ptr<obj_cgroup> objcg;

    public char @Size(16) [] name;

    public mutex freeze_mutex;

    public atomic64_t refcnt;

    public atomic64_t usercnt;

    @InlineUnion(2205)
    public work_struct work;

    @InlineUnion(2205)
    public callback_head rcu;

    public atomic64_t writecnt;

    public @OriginalName("spinlock_t") spinlock owner_lock;

    public Ptr<bpf_map_owner> owner;

    public boolean bypass_spec_v1;

    public boolean frozen;

    public boolean free_after_mult_rcu_gp;

    public boolean free_after_rcu_gp;

    public atomic64_t sleepable_refcnt;

    public Ptr<java.lang.Long> elem_count;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_aux"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_aux extends Struct {
    public atomic64_t refcnt;

    public @Unsigned int used_map_cnt;

    public @Unsigned int used_btf_cnt;

    public @Unsigned int max_ctx_offset;

    public @Unsigned int max_pkt_offset;

    public @Unsigned int max_tp_access;

    public @Unsigned int stack_depth;

    public @Unsigned int id;

    public @Unsigned int func_cnt;

    public @Unsigned int real_func_cnt;

    public @Unsigned int func_idx;

    public @Unsigned int attach_btf_id;

    public @Unsigned int attach_st_ops_member_off;

    public @Unsigned int ctx_arg_info_size;

    public @Unsigned int max_rdonly_access;

    public @Unsigned int max_rdwr_access;

    public Ptr<btf> attach_btf;

    public Ptr<bpf_ctx_arg_aux> ctx_arg_info;

    public Ptr<?> priv_stack_ptr;

    public mutex dst_mutex;

    public Ptr<bpf_prog> dst_prog;

    public Ptr<bpf_trampoline> dst_trampoline;

    public bpf_prog_type saved_dst_prog_type;

    public bpf_attach_type saved_dst_attach_type;

    public boolean verifier_zext;

    public boolean dev_bound;

    public boolean offload_requested;

    public boolean attach_btf_trace;

    public boolean attach_tracing_prog;

    public boolean func_proto_unreliable;

    public boolean tail_call_reachable;

    public boolean xdp_has_frags;

    public boolean exception_cb;

    public boolean exception_boundary;

    public boolean is_extended;

    public boolean jits_use_priv_stack;

    public boolean priv_stack_requested;

    public boolean changes_pkt_data;

    public boolean might_sleep;

    public @Unsigned long prog_array_member_cnt;

    public mutex ext_mutex;

    public Ptr<bpf_arena> arena;

    public Ptr<?> recursion_detected;

    public Ptr<btf_type> attach_func_proto;

    public String attach_func_name;

    public Ptr<Ptr<bpf_prog>> func;

    public Ptr<?> jit_data;

    public Ptr<bpf_jit_poke_descriptor> poke_tab;

    public Ptr<bpf_kfunc_desc_tab> kfunc_tab;

    public Ptr<bpf_kfunc_btf_tab> kfunc_btf_tab;

    public @Unsigned int size_poke_tab;

    public bpf_ksym ksym;

    public Ptr<bpf_prog_ops> ops;

    public Ptr<bpf_struct_ops> st_ops;

    public Ptr<Ptr<bpf_map>> used_maps;

    public mutex used_maps_mutex;

    public Ptr<btf_mod_pair> used_btfs;

    public Ptr<bpf_prog> prog;

    public Ptr<user_struct> user;

    public @Unsigned long load_time;

    public @Unsigned int verified_insns;

    public int cgroup_atype;

    public Ptr<bpf_map> @Size(2) [] cgroup_storage;

    public char @Size(16) [] name;

    public Ptr<?> bpf_exception_cb;

    public Ptr<?> security;

    public Ptr<bpf_token> token;

    public Ptr<bpf_prog_offload> offload;

    public Ptr<btf> btf;

    public Ptr<bpf_func_info> func_info;

    public Ptr<bpf_func_info_aux> func_info_aux;

    public Ptr<bpf_line_info> linfo;

    public Ptr<Ptr<?>> jited_linfo;

    public @Unsigned int func_info_cnt;

    public @Unsigned int nr_linfo;

    public @Unsigned int linfo_idx;

    public Ptr<module> mod;

    public @Unsigned int num_exentries;

    public Ptr<exception_table_entry> extable;

    @InlineUnion(2205)
    public work_struct work;

    @InlineUnion(2205)
    public callback_head rcu;

    public bpf_stream @Size(2) [] stream;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map_owner"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map_owner extends Struct {
    public bpf_prog_type type;

    public boolean jited;

    public boolean xdp_has_frags;

    public @Unsigned long @Size(2) [] storage_cookie;

    public Ptr<btf_type> attach_func_proto;

    public bpf_attach_type expected_attach_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_arg_type"
  )
  public enum bpf_arg_type implements Enum<bpf_arg_type>, TypedEnum<bpf_arg_type, java.lang. @Unsigned Integer> {
    /**
     * {@code ARG_DONTCARE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ARG_DONTCARE"
    )
    ARG_DONTCARE,

    /**
     * {@code ARG_CONST_MAP_PTR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ARG_CONST_MAP_PTR"
    )
    ARG_CONST_MAP_PTR,

    /**
     * {@code ARG_PTR_TO_MAP_KEY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ARG_PTR_TO_MAP_KEY"
    )
    ARG_PTR_TO_MAP_KEY,

    /**
     * {@code ARG_PTR_TO_MAP_VALUE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ARG_PTR_TO_MAP_VALUE"
    )
    ARG_PTR_TO_MAP_VALUE,

    /**
     * {@code ARG_PTR_TO_MEM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ARG_PTR_TO_MEM"
    )
    ARG_PTR_TO_MEM,

    /**
     * {@code ARG_PTR_TO_ARENA = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ARG_PTR_TO_ARENA"
    )
    ARG_PTR_TO_ARENA,

    /**
     * {@code ARG_CONST_SIZE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ARG_CONST_SIZE"
    )
    ARG_CONST_SIZE,

    /**
     * {@code ARG_CONST_SIZE_OR_ZERO = 7}
     */
    @EnumMember(
        value = 7L,
        name = "ARG_CONST_SIZE_OR_ZERO"
    )
    ARG_CONST_SIZE_OR_ZERO,

    /**
     * {@code ARG_PTR_TO_CTX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ARG_PTR_TO_CTX"
    )
    ARG_PTR_TO_CTX,

    /**
     * {@code ARG_ANYTHING = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ARG_ANYTHING"
    )
    ARG_ANYTHING,

    /**
     * {@code ARG_PTR_TO_SPIN_LOCK = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ARG_PTR_TO_SPIN_LOCK"
    )
    ARG_PTR_TO_SPIN_LOCK,

    /**
     * {@code ARG_PTR_TO_SOCK_COMMON = 11}
     */
    @EnumMember(
        value = 11L,
        name = "ARG_PTR_TO_SOCK_COMMON"
    )
    ARG_PTR_TO_SOCK_COMMON,

    /**
     * {@code ARG_PTR_TO_SOCKET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "ARG_PTR_TO_SOCKET"
    )
    ARG_PTR_TO_SOCKET,

    /**
     * {@code ARG_PTR_TO_BTF_ID = 13}
     */
    @EnumMember(
        value = 13L,
        name = "ARG_PTR_TO_BTF_ID"
    )
    ARG_PTR_TO_BTF_ID,

    /**
     * {@code ARG_PTR_TO_RINGBUF_MEM = 14}
     */
    @EnumMember(
        value = 14L,
        name = "ARG_PTR_TO_RINGBUF_MEM"
    )
    ARG_PTR_TO_RINGBUF_MEM,

    /**
     * {@code ARG_CONST_ALLOC_SIZE_OR_ZERO = 15}
     */
    @EnumMember(
        value = 15L,
        name = "ARG_CONST_ALLOC_SIZE_OR_ZERO"
    )
    ARG_CONST_ALLOC_SIZE_OR_ZERO,

    /**
     * {@code ARG_PTR_TO_BTF_ID_SOCK_COMMON = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ARG_PTR_TO_BTF_ID_SOCK_COMMON"
    )
    ARG_PTR_TO_BTF_ID_SOCK_COMMON,

    /**
     * {@code ARG_PTR_TO_PERCPU_BTF_ID = 17}
     */
    @EnumMember(
        value = 17L,
        name = "ARG_PTR_TO_PERCPU_BTF_ID"
    )
    ARG_PTR_TO_PERCPU_BTF_ID,

    /**
     * {@code ARG_PTR_TO_FUNC = 18}
     */
    @EnumMember(
        value = 18L,
        name = "ARG_PTR_TO_FUNC"
    )
    ARG_PTR_TO_FUNC,

    /**
     * {@code ARG_PTR_TO_STACK = 19}
     */
    @EnumMember(
        value = 19L,
        name = "ARG_PTR_TO_STACK"
    )
    ARG_PTR_TO_STACK,

    /**
     * {@code ARG_PTR_TO_CONST_STR = 20}
     */
    @EnumMember(
        value = 20L,
        name = "ARG_PTR_TO_CONST_STR"
    )
    ARG_PTR_TO_CONST_STR,

    /**
     * {@code ARG_PTR_TO_TIMER = 21}
     */
    @EnumMember(
        value = 21L,
        name = "ARG_PTR_TO_TIMER"
    )
    ARG_PTR_TO_TIMER,

    /**
     * {@code ARG_KPTR_XCHG_DEST = 22}
     */
    @EnumMember(
        value = 22L,
        name = "ARG_KPTR_XCHG_DEST"
    )
    ARG_KPTR_XCHG_DEST,

    /**
     * {@code ARG_PTR_TO_DYNPTR = 23}
     */
    @EnumMember(
        value = 23L,
        name = "ARG_PTR_TO_DYNPTR"
    )
    ARG_PTR_TO_DYNPTR,

    /**
     * {@code __BPF_ARG_TYPE_MAX = 24}
     */
    @EnumMember(
        value = 24L,
        name = "__BPF_ARG_TYPE_MAX"
    )
    __BPF_ARG_TYPE_MAX,

    /**
     * {@code ARG_PTR_TO_MAP_VALUE_OR_NULL = 259}
     */
    @EnumMember(
        value = 259L,
        name = "ARG_PTR_TO_MAP_VALUE_OR_NULL"
    )
    ARG_PTR_TO_MAP_VALUE_OR_NULL,

    /**
     * {@code ARG_PTR_TO_MEM_OR_NULL = 260}
     */
    @EnumMember(
        value = 260L,
        name = "ARG_PTR_TO_MEM_OR_NULL"
    )
    ARG_PTR_TO_MEM_OR_NULL,

    /**
     * {@code ARG_PTR_TO_CTX_OR_NULL = 264}
     */
    @EnumMember(
        value = 264L,
        name = "ARG_PTR_TO_CTX_OR_NULL"
    )
    ARG_PTR_TO_CTX_OR_NULL,

    /**
     * {@code ARG_PTR_TO_SOCKET_OR_NULL = 268}
     */
    @EnumMember(
        value = 268L,
        name = "ARG_PTR_TO_SOCKET_OR_NULL"
    )
    ARG_PTR_TO_SOCKET_OR_NULL,

    /**
     * {@code ARG_PTR_TO_STACK_OR_NULL = 275}
     */
    @EnumMember(
        value = 275L,
        name = "ARG_PTR_TO_STACK_OR_NULL"
    )
    ARG_PTR_TO_STACK_OR_NULL,

    /**
     * {@code ARG_PTR_TO_BTF_ID_OR_NULL = 269}
     */
    @EnumMember(
        value = 269L,
        name = "ARG_PTR_TO_BTF_ID_OR_NULL"
    )
    ARG_PTR_TO_BTF_ID_OR_NULL,

    /**
     * {@code ARG_PTR_TO_UNINIT_MEM = 67141636}
     */
    @EnumMember(
        value = 67141636L,
        name = "ARG_PTR_TO_UNINIT_MEM"
    )
    ARG_PTR_TO_UNINIT_MEM,

    /**
     * {@code ARG_PTR_TO_FIXED_SIZE_MEM = 262148}
     */
    @EnumMember(
        value = 262148L,
        name = "ARG_PTR_TO_FIXED_SIZE_MEM"
    )
    ARG_PTR_TO_FIXED_SIZE_MEM,

    /**
     * {@code __BPF_ARG_TYPE_LIMIT = 134217727}
     */
    @EnumMember(
        value = 134217727L,
        name = "__BPF_ARG_TYPE_LIMIT"
    )
    __BPF_ARG_TYPE_LIMIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_return_type"
  )
  public enum bpf_return_type implements Enum<bpf_return_type>, TypedEnum<bpf_return_type, java.lang. @Unsigned Integer> {
    /**
     * {@code RET_INTEGER = 0}
     */
    @EnumMember(
        value = 0L,
        name = "RET_INTEGER"
    )
    RET_INTEGER,

    /**
     * {@code RET_VOID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "RET_VOID"
    )
    RET_VOID,

    /**
     * {@code RET_PTR_TO_MAP_VALUE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "RET_PTR_TO_MAP_VALUE"
    )
    RET_PTR_TO_MAP_VALUE,

    /**
     * {@code RET_PTR_TO_SOCKET = 3}
     */
    @EnumMember(
        value = 3L,
        name = "RET_PTR_TO_SOCKET"
    )
    RET_PTR_TO_SOCKET,

    /**
     * {@code RET_PTR_TO_TCP_SOCK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "RET_PTR_TO_TCP_SOCK"
    )
    RET_PTR_TO_TCP_SOCK,

    /**
     * {@code RET_PTR_TO_SOCK_COMMON = 5}
     */
    @EnumMember(
        value = 5L,
        name = "RET_PTR_TO_SOCK_COMMON"
    )
    RET_PTR_TO_SOCK_COMMON,

    /**
     * {@code RET_PTR_TO_MEM = 6}
     */
    @EnumMember(
        value = 6L,
        name = "RET_PTR_TO_MEM"
    )
    RET_PTR_TO_MEM,

    /**
     * {@code RET_PTR_TO_MEM_OR_BTF_ID = 7}
     */
    @EnumMember(
        value = 7L,
        name = "RET_PTR_TO_MEM_OR_BTF_ID"
    )
    RET_PTR_TO_MEM_OR_BTF_ID,

    /**
     * {@code RET_PTR_TO_BTF_ID = 8}
     */
    @EnumMember(
        value = 8L,
        name = "RET_PTR_TO_BTF_ID"
    )
    RET_PTR_TO_BTF_ID,

    /**
     * {@code __BPF_RET_TYPE_MAX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "__BPF_RET_TYPE_MAX"
    )
    __BPF_RET_TYPE_MAX,

    /**
     * {@code RET_PTR_TO_MAP_VALUE_OR_NULL = 258}
     */
    @EnumMember(
        value = 258L,
        name = "RET_PTR_TO_MAP_VALUE_OR_NULL"
    )
    RET_PTR_TO_MAP_VALUE_OR_NULL,

    /**
     * {@code RET_PTR_TO_SOCKET_OR_NULL = 259}
     */
    @EnumMember(
        value = 259L,
        name = "RET_PTR_TO_SOCKET_OR_NULL"
    )
    RET_PTR_TO_SOCKET_OR_NULL,

    /**
     * {@code RET_PTR_TO_TCP_SOCK_OR_NULL = 260}
     */
    @EnumMember(
        value = 260L,
        name = "RET_PTR_TO_TCP_SOCK_OR_NULL"
    )
    RET_PTR_TO_TCP_SOCK_OR_NULL,

    /**
     * {@code RET_PTR_TO_SOCK_COMMON_OR_NULL = 261}
     */
    @EnumMember(
        value = 261L,
        name = "RET_PTR_TO_SOCK_COMMON_OR_NULL"
    )
    RET_PTR_TO_SOCK_COMMON_OR_NULL,

    /**
     * {@code RET_PTR_TO_RINGBUF_MEM_OR_NULL = 1286}
     */
    @EnumMember(
        value = 1286L,
        name = "RET_PTR_TO_RINGBUF_MEM_OR_NULL"
    )
    RET_PTR_TO_RINGBUF_MEM_OR_NULL,

    /**
     * {@code RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262}
     */
    @EnumMember(
        value = 262L,
        name = "RET_PTR_TO_DYNPTR_MEM_OR_NULL"
    )
    RET_PTR_TO_DYNPTR_MEM_OR_NULL,

    /**
     * {@code RET_PTR_TO_BTF_ID_OR_NULL = 264}
     */
    @EnumMember(
        value = 264L,
        name = "RET_PTR_TO_BTF_ID_OR_NULL"
    )
    RET_PTR_TO_BTF_ID_OR_NULL,

    /**
     * {@code RET_PTR_TO_BTF_ID_TRUSTED = 1048584}
     */
    @EnumMember(
        value = 1048584L,
        name = "RET_PTR_TO_BTF_ID_TRUSTED"
    )
    RET_PTR_TO_BTF_ID_TRUSTED,

    /**
     * {@code __BPF_RET_TYPE_LIMIT = 134217727}
     */
    @EnumMember(
        value = 134217727L,
        name = "__BPF_RET_TYPE_LIMIT"
    )
    __BPF_RET_TYPE_LIMIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_func_proto"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_func_proto extends Struct {
    public Ptr<?> func;

    public boolean gpl_only;

    public boolean pkt_access;

    public boolean might_sleep;

    public boolean allow_fastcall;

    public bpf_return_type ret_type;

    @InlineUnion(2213)
    public anon_member_of_anon_member_of_bpf_func_proto anon6$0;

    @InlineUnion(2213)
    public bpf_arg_type @Size(5) [] arg_type;

    @InlineUnion(2217)
    public anon_member_of_anon_member_of_bpf_func_proto anon7$0;

    @InlineUnion(2217)
    public Ptr<java.lang. @Unsigned Integer> @Size(5) [] arg_btf_id;

    @InlineUnion(2217)
    public anon_member_of_anon_member_of_bpf_func_proto anon7$2;

    @InlineUnion(2217)
    public @Unsigned long @Size(5) [] arg_size;

    public Ptr<java.lang.Integer> ret_btf_id;

    public Ptr<?> allowed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_access_type"
  )
  public enum bpf_access_type implements Enum<bpf_access_type>, TypedEnum<bpf_access_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_READ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_READ"
    )
    BPF_READ,

    /**
     * {@code BPF_WRITE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_WRITE"
    )
    BPF_WRITE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_reg_type"
  )
  public enum bpf_reg_type implements Enum<bpf_reg_type>, TypedEnum<bpf_reg_type, java.lang. @Unsigned Integer> {
    /**
     * {@code NOT_INIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NOT_INIT"
    )
    NOT_INIT,

    /**
     * {@code SCALAR_VALUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCALAR_VALUE"
    )
    SCALAR_VALUE,

    /**
     * {@code PTR_TO_CTX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PTR_TO_CTX"
    )
    PTR_TO_CTX,

    /**
     * {@code CONST_PTR_TO_MAP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "CONST_PTR_TO_MAP"
    )
    CONST_PTR_TO_MAP,

    /**
     * {@code PTR_TO_MAP_VALUE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PTR_TO_MAP_VALUE"
    )
    PTR_TO_MAP_VALUE,

    /**
     * {@code PTR_TO_MAP_KEY = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PTR_TO_MAP_KEY"
    )
    PTR_TO_MAP_KEY,

    /**
     * {@code PTR_TO_STACK = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PTR_TO_STACK"
    )
    PTR_TO_STACK,

    /**
     * {@code PTR_TO_PACKET_META = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PTR_TO_PACKET_META"
    )
    PTR_TO_PACKET_META,

    /**
     * {@code PTR_TO_PACKET = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PTR_TO_PACKET"
    )
    PTR_TO_PACKET,

    /**
     * {@code PTR_TO_PACKET_END = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PTR_TO_PACKET_END"
    )
    PTR_TO_PACKET_END,

    /**
     * {@code PTR_TO_FLOW_KEYS = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PTR_TO_FLOW_KEYS"
    )
    PTR_TO_FLOW_KEYS,

    /**
     * {@code PTR_TO_SOCKET = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PTR_TO_SOCKET"
    )
    PTR_TO_SOCKET,

    /**
     * {@code PTR_TO_SOCK_COMMON = 12}
     */
    @EnumMember(
        value = 12L,
        name = "PTR_TO_SOCK_COMMON"
    )
    PTR_TO_SOCK_COMMON,

    /**
     * {@code PTR_TO_TCP_SOCK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "PTR_TO_TCP_SOCK"
    )
    PTR_TO_TCP_SOCK,

    /**
     * {@code PTR_TO_TP_BUFFER = 14}
     */
    @EnumMember(
        value = 14L,
        name = "PTR_TO_TP_BUFFER"
    )
    PTR_TO_TP_BUFFER,

    /**
     * {@code PTR_TO_XDP_SOCK = 15}
     */
    @EnumMember(
        value = 15L,
        name = "PTR_TO_XDP_SOCK"
    )
    PTR_TO_XDP_SOCK,

    /**
     * {@code PTR_TO_BTF_ID = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PTR_TO_BTF_ID"
    )
    PTR_TO_BTF_ID,

    /**
     * {@code PTR_TO_MEM = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PTR_TO_MEM"
    )
    PTR_TO_MEM,

    /**
     * {@code PTR_TO_ARENA = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PTR_TO_ARENA"
    )
    PTR_TO_ARENA,

    /**
     * {@code PTR_TO_BUF = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PTR_TO_BUF"
    )
    PTR_TO_BUF,

    /**
     * {@code PTR_TO_FUNC = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PTR_TO_FUNC"
    )
    PTR_TO_FUNC,

    /**
     * {@code CONST_PTR_TO_DYNPTR = 21}
     */
    @EnumMember(
        value = 21L,
        name = "CONST_PTR_TO_DYNPTR"
    )
    CONST_PTR_TO_DYNPTR,

    /**
     * {@code __BPF_REG_TYPE_MAX = 22}
     */
    @EnumMember(
        value = 22L,
        name = "__BPF_REG_TYPE_MAX"
    )
    __BPF_REG_TYPE_MAX,

    /**
     * {@code PTR_TO_MAP_VALUE_OR_NULL = 260}
     */
    @EnumMember(
        value = 260L,
        name = "PTR_TO_MAP_VALUE_OR_NULL"
    )
    PTR_TO_MAP_VALUE_OR_NULL,

    /**
     * {@code PTR_TO_SOCKET_OR_NULL = 267}
     */
    @EnumMember(
        value = 267L,
        name = "PTR_TO_SOCKET_OR_NULL"
    )
    PTR_TO_SOCKET_OR_NULL,

    /**
     * {@code PTR_TO_SOCK_COMMON_OR_NULL = 268}
     */
    @EnumMember(
        value = 268L,
        name = "PTR_TO_SOCK_COMMON_OR_NULL"
    )
    PTR_TO_SOCK_COMMON_OR_NULL,

    /**
     * {@code PTR_TO_TCP_SOCK_OR_NULL = 269}
     */
    @EnumMember(
        value = 269L,
        name = "PTR_TO_TCP_SOCK_OR_NULL"
    )
    PTR_TO_TCP_SOCK_OR_NULL,

    /**
     * {@code PTR_TO_BTF_ID_OR_NULL = 272}
     */
    @EnumMember(
        value = 272L,
        name = "PTR_TO_BTF_ID_OR_NULL"
    )
    PTR_TO_BTF_ID_OR_NULL,

    /**
     * {@code __BPF_REG_TYPE_LIMIT = 134217727}
     */
    @EnumMember(
        value = 134217727L,
        name = "__BPF_REG_TYPE_LIMIT"
    )
    __BPF_REG_TYPE_LIMIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_insn_access_aux"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_insn_access_aux extends Struct {
    public bpf_reg_type reg_type;

    public boolean is_ldsx;

    @InlineUnion(2227)
    public int ctx_field_size;

    @InlineUnion(2227)
    public anon_member_of_anon_member_of_bpf_insn_access_aux anon2$1;

    public Ptr<bpf_verifier_log> log;

    public boolean is_retval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_ops extends Struct {
    public Ptr<?> test_run;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_ops extends Struct {
    public Ptr<?> get_func_proto;

    public Ptr<?> is_valid_access;

    public Ptr<?> gen_prologue;

    public Ptr<?> gen_epilogue;

    public Ptr<?> gen_ld_abs;

    public Ptr<?> convert_ctx_access;

    public Ptr<?> btf_struct_access;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_reg_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_reg_state extends Struct {
    public bpf_reg_type type;

    public int off;

    @InlineUnion(11830)
    public int range;

    @InlineUnion(11830)
    public anon_member_of_anon_member_of_bpf_reg_state anon2$1;

    @InlineUnion(11830)
    public anon_member_of_anon_member_of_bpf_reg_state_and_anon_member_of_anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data anon2$2;

    @InlineUnion(11830)
    public anon_member_of_anon_member_of_bpf_reg_state anon2$3;

    @InlineUnion(11830)
    public dynptr_of_anon_member_of_bpf_reg_state dynptr;

    @InlineUnion(11830)
    public iter_of_anon_member_of_bpf_reg_state iter;

    @InlineUnion(11830)
    public irq_of_anon_member_of_bpf_reg_state irq;

    @InlineUnion(11830)
    public raw_of_anon_member_of_bpf_reg_state raw;

    @InlineUnion(11830)
    public @Unsigned int subprogno;

    public tnum var_off;

    public long smin_value;

    public long smax_value;

    public @Unsigned long umin_value;

    public @Unsigned long umax_value;

    public int s32_min_value;

    public int s32_max_value;

    public @Unsigned int u32_min_value;

    public @Unsigned int u32_max_value;

    public @Unsigned int id;

    public @Unsigned int ref_obj_id;

    public Ptr<bpf_reg_state> parent;

    public @Unsigned int frameno;

    public int subreg_def;

    public bpf_reg_liveness live;

    public boolean precise;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_offload extends Struct {
    public Ptr<bpf_prog> prog;

    public Ptr<net_device> netdev;

    public Ptr<bpf_offload_dev> offdev;

    public Ptr<?> dev_priv;

    public list_head offloads;

    public boolean dev_state;

    public boolean opt_failed;

    public Ptr<?> jited_image;

    public @Unsigned int jited_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ksym"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ksym extends Struct {
    public @Unsigned long start;

    public @Unsigned long end;

    public char @Size(512) [] name;

    public list_head lnode;

    public latch_tree_node tnode;

    public boolean prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tramp_image"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tramp_image extends Struct {
    public Ptr<?> image;

    public int size;

    public bpf_ksym ksym;

    public percpu_ref pcref;

    public Ptr<?> ip_after_call;

    public Ptr<?> ip_epilogue;

    @InlineUnion(2262)
    public callback_head rcu;

    @InlineUnion(2262)
    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_trampoline"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_trampoline extends Struct {
    public hlist_node hlist;

    public Ptr<ftrace_ops> fops;

    public mutex mutex;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int flags;

    public @Unsigned long key;

    public func_of_bpf_trampoline func;

    public Ptr<bpf_prog> extension_prog;

    public hlist_head @Size(3) [] progs_hlist;

    public int @Size(3) [] progs_cnt;

    public Ptr<bpf_tramp_image> cur_image;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_func_info_aux"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_func_info_aux extends Struct {
    public @Unsigned short linkage;

    public boolean unreliable;

    public boolean called;

    public boolean verified;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_jit_poke_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_jit_poke_descriptor extends Struct {
    public Ptr<?> tailcall_target;

    public Ptr<?> tailcall_bypass;

    public Ptr<?> bypass_addr;

    public Ptr<?> aux;

    @InlineUnion(2271)
    public tail_call_of_anon_member_of_bpf_jit_poke_descriptor tail_call;

    public boolean tailcall_target_stable;

    public char adj_off;

    public @Unsigned short reason;

    public @Unsigned int insn_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ctx_arg_aux"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ctx_arg_aux extends Struct {
    public @Unsigned int offset;

    public bpf_reg_type reg_type;

    public Ptr<btf> btf;

    public @Unsigned int btf_id;

    public @Unsigned int ref_obj_id;

    public boolean refcounted;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stream"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stream extends Struct {
    public atomic_t capacity;

    public llist_head log;

    public mutex lock;

    public Ptr<llist_node> backlog_head;

    public Ptr<llist_node> backlog_tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops extends Struct {
    public Ptr<bpf_verifier_ops> verifier_ops;

    public Ptr<?> init;

    public Ptr<?> check_member;

    public Ptr<?> init_member;

    public Ptr<?> reg;

    public Ptr<?> unreg;

    public Ptr<?> update;

    public Ptr<?> validate;

    public Ptr<?> cfi_stubs;

    public Ptr<module> owner;

    public String name;

    public btf_func_model @Size(64) [] func_models;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_token"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_token extends Struct {
    public work_struct work;

    public atomic64_t refcnt;

    public Ptr<user_namespace> userns;

    public @Unsigned long allowed_cmds;

    public @Unsigned long allowed_maps;

    public @Unsigned long allowed_progs;

    public @Unsigned long allowed_attachs;

    public Ptr<?> security;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_link extends Struct {
    public atomic64_t refcnt;

    public @Unsigned int id;

    public bpf_link_type type;

    public Ptr<bpf_link_ops> ops;

    public Ptr<bpf_prog> prog;

    public @Unsigned int flags;

    public bpf_attach_type attach_type;

    @InlineUnion(2262)
    public callback_head rcu;

    @InlineUnion(2262)
    public work_struct work;

    public boolean sleepable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_link_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_link_ops extends Struct {
    public Ptr<?> release;

    public Ptr<?> dealloc;

    public Ptr<?> dealloc_deferred;

    public Ptr<?> detach;

    public Ptr<?> update_prog;

    public Ptr<?> show_fdinfo;

    public Ptr<?> fill_link_info;

    public Ptr<?> update_map;

    public Ptr<?> poll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_tp_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_tp_link extends Struct {
    public bpf_link link;

    public Ptr<bpf_raw_event_map> btp;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_array_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_array_item extends Struct {
    public Ptr<bpf_prog> prog;

    @InlineUnion(2343)
    public Ptr<bpf_cgroup_storage> @Size(2) [] cgroup_storage;

    @InlineUnion(2343)
    public @Unsigned long bpf_cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_iter_task_type"
  )
  public enum bpf_iter_task_type implements Enum<bpf_iter_task_type>, TypedEnum<bpf_iter_task_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_TASK_ITER_ALL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_TASK_ITER_ALL"
    )
    BPF_TASK_ITER_ALL,

    /**
     * {@code BPF_TASK_ITER_TID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_TASK_ITER_TID"
    )
    BPF_TASK_ITER_TID,

    /**
     * {@code BPF_TASK_ITER_TGID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_TASK_ITER_TGID"
    )
    BPF_TASK_ITER_TGID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map_dev_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map_dev_ops extends Struct {
    public Ptr<?> map_get_next_key;

    public Ptr<?> map_lookup_elem;

    public Ptr<?> map_update_elem;

    public Ptr<?> map_delete_elem;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_offloaded_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_offloaded_map extends Struct {
    public bpf_map map;

    public Ptr<net_device> netdev;

    public Ptr<bpf_map_dev_ops> dev_ops;

    public Ptr<?> dev_priv;

    public list_head offloads;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_netdev_command"
  )
  public enum bpf_netdev_command implements Enum<bpf_netdev_command>, TypedEnum<bpf_netdev_command, java.lang. @Unsigned Integer> {
    /**
     * {@code XDP_SETUP_PROG = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XDP_SETUP_PROG"
    )
    XDP_SETUP_PROG,

    /**
     * {@code XDP_SETUP_PROG_HW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XDP_SETUP_PROG_HW"
    )
    XDP_SETUP_PROG_HW,

    /**
     * {@code BPF_OFFLOAD_MAP_ALLOC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_OFFLOAD_MAP_ALLOC"
    )
    BPF_OFFLOAD_MAP_ALLOC,

    /**
     * {@code BPF_OFFLOAD_MAP_FREE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_OFFLOAD_MAP_FREE"
    )
    BPF_OFFLOAD_MAP_FREE,

    /**
     * {@code XDP_SETUP_XSK_POOL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "XDP_SETUP_XSK_POOL"
    )
    XDP_SETUP_XSK_POOL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_xdp_entity"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_xdp_entity extends Struct {
    public Ptr<bpf_prog> prog;

    public Ptr<bpf_xdp_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_cgroup_storage_type"
  )
  public enum bpf_cgroup_storage_type implements Enum<bpf_cgroup_storage_type>, TypedEnum<bpf_cgroup_storage_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_CGROUP_STORAGE_SHARED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_CGROUP_STORAGE_SHARED"
    )
    BPF_CGROUP_STORAGE_SHARED,

    /**
     * {@code BPF_CGROUP_STORAGE_PERCPU = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_CGROUP_STORAGE_PERCPU"
    )
    BPF_CGROUP_STORAGE_PERCPU,

    /**
     * {@code __BPF_CGROUP_STORAGE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__BPF_CGROUP_STORAGE_MAX"
    )
    __BPF_CGROUP_STORAGE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_type_flag"
  )
  public enum bpf_type_flag implements Enum<bpf_type_flag>, TypedEnum<bpf_type_flag, java.lang. @Unsigned Integer> {
    /**
     * {@code PTR_MAYBE_NULL = 256}
     */
    @EnumMember(
        value = 256L,
        name = "PTR_MAYBE_NULL"
    )
    PTR_MAYBE_NULL,

    /**
     * {@code MEM_RDONLY = 512}
     */
    @EnumMember(
        value = 512L,
        name = "MEM_RDONLY"
    )
    MEM_RDONLY,

    /**
     * {@code MEM_RINGBUF = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "MEM_RINGBUF"
    )
    MEM_RINGBUF,

    /**
     * {@code MEM_USER = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "MEM_USER"
    )
    MEM_USER,

    /**
     * {@code MEM_PERCPU = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "MEM_PERCPU"
    )
    MEM_PERCPU,

    /**
     * {@code OBJ_RELEASE = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "OBJ_RELEASE"
    )
    OBJ_RELEASE,

    /**
     * {@code PTR_UNTRUSTED = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "PTR_UNTRUSTED"
    )
    PTR_UNTRUSTED,

    /**
     * {@code MEM_UNINIT = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "MEM_UNINIT"
    )
    MEM_UNINIT,

    /**
     * {@code DYNPTR_TYPE_LOCAL = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "DYNPTR_TYPE_LOCAL"
    )
    DYNPTR_TYPE_LOCAL,

    /**
     * {@code DYNPTR_TYPE_RINGBUF = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "DYNPTR_TYPE_RINGBUF"
    )
    DYNPTR_TYPE_RINGBUF,

    /**
     * {@code MEM_FIXED_SIZE = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "MEM_FIXED_SIZE"
    )
    MEM_FIXED_SIZE,

    /**
     * {@code MEM_ALLOC = 524288}
     */
    @EnumMember(
        value = 524288L,
        name = "MEM_ALLOC"
    )
    MEM_ALLOC,

    /**
     * {@code PTR_TRUSTED = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "PTR_TRUSTED"
    )
    PTR_TRUSTED,

    /**
     * {@code MEM_RCU = 2097152}
     */
    @EnumMember(
        value = 2097152L,
        name = "MEM_RCU"
    )
    MEM_RCU,

    /**
     * {@code NON_OWN_REF = 4194304}
     */
    @EnumMember(
        value = 4194304L,
        name = "NON_OWN_REF"
    )
    NON_OWN_REF,

    /**
     * {@code DYNPTR_TYPE_SKB = 8388608}
     */
    @EnumMember(
        value = 8388608L,
        name = "DYNPTR_TYPE_SKB"
    )
    DYNPTR_TYPE_SKB,

    /**
     * {@code DYNPTR_TYPE_XDP = 16777216}
     */
    @EnumMember(
        value = 16777216L,
        name = "DYNPTR_TYPE_XDP"
    )
    DYNPTR_TYPE_XDP,

    /**
     * {@code MEM_ALIGNED = 33554432}
     */
    @EnumMember(
        value = 33554432L,
        name = "MEM_ALIGNED"
    )
    MEM_ALIGNED,

    /**
     * {@code MEM_WRITE = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "MEM_WRITE"
    )
    MEM_WRITE,

    /**
     * {@code __BPF_TYPE_FLAG_MAX = 67108865}
     */
    @EnumMember(
        value = 67108865L,
        name = "__BPF_TYPE_FLAG_MAX"
    )
    __BPF_TYPE_FLAG_MAX,

    /**
     * {@code __BPF_TYPE_LAST_FLAG = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "__BPF_TYPE_LAST_FLAG"
    )
    __BPF_TYPE_LAST_FLAG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_tramp_prog_type"
  )
  public enum bpf_tramp_prog_type implements Enum<bpf_tramp_prog_type>, TypedEnum<bpf_tramp_prog_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_TRAMP_FENTRY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_TRAMP_FENTRY"
    )
    BPF_TRAMP_FENTRY,

    /**
     * {@code BPF_TRAMP_FEXIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_TRAMP_FEXIT"
    )
    BPF_TRAMP_FEXIT,

    /**
     * {@code BPF_TRAMP_MODIFY_RETURN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_TRAMP_MODIFY_RETURN"
    )
    BPF_TRAMP_MODIFY_RETURN,

    /**
     * {@code BPF_TRAMP_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_TRAMP_MAX"
    )
    BPF_TRAMP_MAX,

    /**
     * {@code BPF_TRAMP_REPLACE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_TRAMP_REPLACE"
    )
    BPF_TRAMP_REPLACE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_net_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_net_context extends Struct {
    public bpf_redirect_info ri;

    public list_head cpu_map_flush_list;

    public list_head dev_map_flush_list;

    public list_head xskmap_map_flush_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_addr_space_cast"
  )
  public enum bpf_addr_space_cast implements Enum<bpf_addr_space_cast>, TypedEnum<bpf_addr_space_cast, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_ADDR_SPACE_CAST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_ADDR_SPACE_CAST"
    )
    BPF_ADDR_SPACE_CAST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tramp_links"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tramp_links extends Struct {
    public Ptr<bpf_tramp_link> @Size(38) [] links;

    public int nr_links;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tramp_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tramp_link extends Struct {
    public bpf_link link;

    public hlist_node tramp_hlist;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tramp_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tramp_run_ctx extends Struct {
    public bpf_run_ctx run_ctx;

    public @Unsigned long bpf_cookie;

    public Ptr<bpf_run_ctx> saved_run_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_jit_poke_reason"
  )
  public enum bpf_jit_poke_reason implements Enum<bpf_jit_poke_reason>, TypedEnum<bpf_jit_poke_reason, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_POKE_REASON_TAIL_CALL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_POKE_REASON_TAIL_CALL"
    )
    BPF_POKE_REASON_TAIL_CALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_stats extends Struct {
    public u64_stats_t cnt;

    public u64_stats_t nsecs;

    public u64_stats_t misses;

    public u64_stats_sync syncp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_array_aux"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_array_aux extends Struct {
    public list_head poke_progs;

    public Ptr<bpf_map> map;

    public mutex poke_mutex;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_array extends Struct {
    public bpf_map map;

    public @Unsigned int elem_size;

    public @Unsigned int index_mask;

    public Ptr<bpf_array_aux> aux;

    @InlineUnion(9804)
    public anon_member_of_anon_member_of_bpf_array anon4$0;

    @InlineUnion(9804)
    public anon_member_of_anon_member_of_bpf_array anon4$1;

    @InlineUnion(9804)
    public anon_member_of_anon_member_of_bpf_array anon4$2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_text_poke_type"
  )
  public enum bpf_text_poke_type implements Enum<bpf_text_poke_type>, TypedEnum<bpf_text_poke_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MOD_CALL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_MOD_CALL"
    )
    BPF_MOD_CALL,

    /**
     * {@code BPF_MOD_JUMP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_MOD_JUMP"
    )
    BPF_MOD_JUMP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_binary_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_binary_header extends Struct {
    public @Unsigned int size;

    public char @Size(0) [] image;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_nh_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_nh_params extends Struct {
    public @Unsigned int nh_family;

    @InlineUnion(9933)
    public @Unsigned int ipv4_nh;

    @InlineUnion(9933)
    public in6_addr ipv6_nh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_redirect_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_redirect_info extends Struct {
    public @Unsigned long tgt_index;

    public Ptr<?> tgt_value;

    public Ptr<bpf_map> map;

    public @Unsigned int flags;

    public @Unsigned int map_id;

    public bpf_map_type map_type;

    public bpf_nh_params nh;

    public @Unsigned int kern_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_xdp_mode"
  )
  public enum bpf_xdp_mode implements Enum<bpf_xdp_mode>, TypedEnum<bpf_xdp_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code XDP_MODE_SKB = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XDP_MODE_SKB"
    )
    XDP_MODE_SKB,

    /**
     * {@code XDP_MODE_DRV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XDP_MODE_DRV"
    )
    XDP_MODE_DRV,

    /**
     * {@code XDP_MODE_HW = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XDP_MODE_HW"
    )
    XDP_MODE_HW,

    /**
     * {@code __MAX_XDP_MODE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__MAX_XDP_MODE"
    )
    __MAX_XDP_MODE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_env"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_env extends Struct {
    public @Unsigned int insn_idx;

    public @Unsigned int prev_insn_idx;

    public Ptr<bpf_prog> prog;

    public Ptr<bpf_verifier_ops> ops;

    public Ptr<module> attach_btf_mod;

    public Ptr<bpf_verifier_stack_elem> head;

    public int stack_size;

    public boolean strict_alignment;

    public boolean test_state_freq;

    public boolean test_reg_invariants;

    public Ptr<bpf_verifier_state> cur_state;

    public Ptr<list_head> explored_states;

    public list_head free_list;

    public Ptr<bpf_map> @Size(64) [] used_maps;

    public btf_mod_pair @Size(64) [] used_btfs;

    public @Unsigned int used_map_cnt;

    public @Unsigned int used_btf_cnt;

    public @Unsigned int id_gen;

    public @Unsigned int hidden_subprog_cnt;

    public int exception_callback_subprog;

    public boolean explore_alu_limits;

    public boolean allow_ptr_leaks;

    public boolean allow_uninit_stack;

    public boolean bpf_capable;

    public boolean bypass_spec_v1;

    public boolean bypass_spec_v4;

    public boolean seen_direct_write;

    public boolean seen_exception;

    public Ptr<bpf_insn_aux_data> insn_aux_data;

    public Ptr<bpf_line_info> prev_linfo;

    public bpf_verifier_log log;

    public bpf_subprog_info @Size(258) [] subprog_info;

    @InlineUnion(11871)
    public bpf_idmap idmap_scratch;

    @InlineUnion(11871)
    public bpf_idset idset_scratch;

    public cfg_of_bpf_verifier_env cfg;

    public backtrack_state bt;

    public Ptr<bpf_jmp_history_entry> cur_hist_ent;

    public @Unsigned int pass_cnt;

    public @Unsigned int subprog_cnt;

    public @Unsigned int prev_insn_processed;

    public @Unsigned int insn_processed;

    public @Unsigned int prev_jmps_processed;

    public @Unsigned int jmps_processed;

    public @Unsigned long verification_time;

    public @Unsigned int max_states_per_insn;

    public @Unsigned int total_states;

    public @Unsigned int peak_states;

    public @Unsigned int longest_mark_read_walk;

    public @Unsigned int free_list_size;

    public @Unsigned int explored_states_size;

    public @Unsigned int num_backedges;

    public @OriginalName("bpfptr_t") sockptr_t fd_array;

    public @Unsigned int scratched_regs;

    public @Unsigned long scratched_stack_slots;

    public @Unsigned long prev_log_pos;

    public @Unsigned long prev_insn_print_pos;

    public bpf_reg_state @Size(2) [] fake_reg;

    public char @Size(320) [] tmp_str_buf;

    public bpf_insn @Size(32) [] insn_buf;

    public bpf_insn @Size(32) [] epilogue_buf;

    public bpf_scc_callchain callchain_buf;

    public Ptr<Ptr<bpf_scc_info>> scc_info;

    public @Unsigned int scc_cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_func_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_func_state extends Struct {
    public bpf_reg_state @Size(11) [] regs;

    public int callsite;

    public @Unsigned int frameno;

    public @Unsigned int subprogno;

    public @Unsigned int async_entry_cnt;

    public bpf_retval_range callback_ret_range;

    public boolean in_callback_fn;

    public boolean in_async_callback_fn;

    public boolean in_exception_callback_fn;

    public @Unsigned int callback_depth;

    public Ptr<bpf_stack_state> stack;

    public int allocated_stack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_log"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_log extends Struct {
    public @Unsigned long start_pos;

    public @Unsigned long end_pos;

    public String ubuf;

    public @Unsigned int level;

    public @Unsigned int len_total;

    public @Unsigned int len_max;

    public char @Size(1024) [] kbuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_dynptr_type"
  )
  public enum bpf_dynptr_type implements Enum<bpf_dynptr_type>, TypedEnum<bpf_dynptr_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_DYNPTR_TYPE_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_DYNPTR_TYPE_INVALID"
    )
    BPF_DYNPTR_TYPE_INVALID,

    /**
     * {@code BPF_DYNPTR_TYPE_LOCAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_DYNPTR_TYPE_LOCAL"
    )
    BPF_DYNPTR_TYPE_LOCAL,

    /**
     * {@code BPF_DYNPTR_TYPE_RINGBUF = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_DYNPTR_TYPE_RINGBUF"
    )
    BPF_DYNPTR_TYPE_RINGBUF,

    /**
     * {@code BPF_DYNPTR_TYPE_SKB = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_DYNPTR_TYPE_SKB"
    )
    BPF_DYNPTR_TYPE_SKB,

    /**
     * {@code BPF_DYNPTR_TYPE_XDP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_DYNPTR_TYPE_XDP"
    )
    BPF_DYNPTR_TYPE_XDP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_struct_ops_state"
  )
  public enum bpf_struct_ops_state implements Enum<bpf_struct_ops_state>, TypedEnum<bpf_struct_ops_state, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_STRUCT_OPS_STATE_INIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_STRUCT_OPS_STATE_INIT"
    )
    BPF_STRUCT_OPS_STATE_INIT,

    /**
     * {@code BPF_STRUCT_OPS_STATE_INUSE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_STRUCT_OPS_STATE_INUSE"
    )
    BPF_STRUCT_OPS_STATE_INUSE,

    /**
     * {@code BPF_STRUCT_OPS_STATE_TOBEFREE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_STRUCT_OPS_STATE_TOBEFREE"
    )
    BPF_STRUCT_OPS_STATE_TOBEFREE,

    /**
     * {@code BPF_STRUCT_OPS_STATE_READY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_STRUCT_OPS_STATE_READY"
    )
    BPF_STRUCT_OPS_STATE_READY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_common_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_common_value extends Struct {
    public @OriginalName("refcount_t") refcount_struct refcnt;

    public bpf_struct_ops_state state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_bprintf_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_bprintf_data extends Struct {
    public Ptr<java.lang. @Unsigned Integer> bin_args;

    public String buf;

    public boolean get_bin_args;

    public boolean get_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_scx_dsq_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_scx_dsq_kern extends Struct {
    public scx_dsq_list_node cursor;

    public Ptr<scx_dispatch_q> dsq;

    public @Unsigned long slice;

    public @Unsigned long vtime;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_scx_dsq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_scx_dsq extends Struct {
    public @Unsigned long @Size(6) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_reg_liveness"
  )
  public enum bpf_reg_liveness implements Enum<bpf_reg_liveness>, TypedEnum<bpf_reg_liveness, java.lang. @Unsigned Integer> {
    /**
     * {@code REG_LIVE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "REG_LIVE_NONE"
    )
    REG_LIVE_NONE,

    /**
     * {@code REG_LIVE_READ32 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "REG_LIVE_READ32"
    )
    REG_LIVE_READ32,

    /**
     * {@code REG_LIVE_READ64 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "REG_LIVE_READ64"
    )
    REG_LIVE_READ64,

    /**
     * {@code REG_LIVE_READ = 3}
     */
    @EnumMember(
        value = 3L,
        name = "REG_LIVE_READ"
    )
    REG_LIVE_READ,

    /**
     * {@code REG_LIVE_WRITTEN = 4}
     */
    @EnumMember(
        value = 4L,
        name = "REG_LIVE_WRITTEN"
    )
    REG_LIVE_WRITTEN,

    /**
     * {@code REG_LIVE_DONE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "REG_LIVE_DONE"
    )
    REG_LIVE_DONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_iter_state"
  )
  public enum bpf_iter_state implements Enum<bpf_iter_state>, TypedEnum<bpf_iter_state, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_ITER_STATE_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_ITER_STATE_INVALID"
    )
    BPF_ITER_STATE_INVALID,

    /**
     * {@code BPF_ITER_STATE_ACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_ITER_STATE_ACTIVE"
    )
    BPF_ITER_STATE_ACTIVE,

    /**
     * {@code BPF_ITER_STATE_DRAINED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_ITER_STATE_DRAINED"
    )
    BPF_ITER_STATE_DRAINED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stack_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stack_state extends Struct {
    public bpf_reg_state spilled_ptr;

    public char @Size(8) [] slot_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_reference_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_reference_state extends Struct {
    public ref_state_type type;

    public int id;

    public int insn_idx;

    public Ptr<?> ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_retval_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_retval_range extends Struct {
    public int minval;

    public int maxval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_jmp_history_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_jmp_history_entry extends Struct {
    public @Unsigned int idx;

    public @Unsigned int prev_idx;

    public @Unsigned int flags;

    public @Unsigned long linked_regs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_state extends Struct {
    public Ptr<bpf_func_state> @Size(8) [] frame;

    public Ptr<bpf_verifier_state> parent;

    public Ptr<bpf_reference_state> refs;

    public @Unsigned int branches;

    public @Unsigned int insn_idx;

    public @Unsigned int curframe;

    public @Unsigned int acquired_refs;

    public @Unsigned int active_locks;

    public @Unsigned int active_preempt_locks;

    public @Unsigned int active_irq_id;

    public @Unsigned int active_lock_id;

    public Ptr<?> active_lock_ptr;

    public boolean active_rcu_lock;

    public boolean speculative;

    public boolean in_sleepable;

    public @Unsigned int first_insn_idx;

    public @Unsigned int last_insn_idx;

    public Ptr<bpf_verifier_state> equal_state;

    public Ptr<bpf_jmp_history_entry> jmp_history;

    public @Unsigned int jmp_history_cnt;

    public @Unsigned int dfs_depth;

    public @Unsigned int callback_unroll_depth;

    public @Unsigned int may_goto_depth;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_loop_inline_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_loop_inline_state extends Struct {
    public @Unsigned int initialized;

    public @Unsigned int fit_for_inline;

    public @Unsigned int callback_subprogno;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map_ptr_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map_ptr_state extends Struct {
    public Ptr<bpf_map> map_ptr;

    public boolean poison;

    public boolean unpriv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_insn_aux_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_insn_aux_data extends Struct {
    @InlineUnion(11850)
    public bpf_reg_type ptr_type;

    @InlineUnion(11850)
    public bpf_map_ptr_state map_ptr_state;

    @InlineUnion(11850)
    public int call_imm;

    @InlineUnion(11850)
    public @Unsigned int alu_limit;

    @InlineUnion(11850)
    public anon_member_of_anon_member_of_bpf_insn_aux_data anon0$4;

    @InlineUnion(11850)
    public btf_var_of_anon_member_of_bpf_insn_aux_data btf_var;

    @InlineUnion(11850)
    public bpf_loop_inline_state loop_inline_state;

    @InlineUnion(11851)
    public @Unsigned long obj_new_size;

    @InlineUnion(11851)
    public @Unsigned long insert_off;

    public Ptr<btf_struct_meta> kptr_struct_meta;

    public @Unsigned long map_key_state;

    public int ctx_field_size;

    public @Unsigned int seen;

    public boolean nospec;

    public boolean nospec_result;

    public boolean zext_dst;

    public boolean needs_zext;

    public boolean storage_get_func_atomic;

    public boolean is_iter_next;

    public boolean call_with_percpu_alloc_ptr;

    public char alu_state;

    public char fastcall_pattern;

    public char fastcall_spills_num;

    public char arg_prog;

    public @Unsigned int orig_idx;

    public boolean jmp_point;

    public boolean prune_point;

    public boolean force_checkpoint;

    public boolean calls_callback;

    public @Unsigned int scc;

    public @Unsigned short live_regs_before;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_subprog_arg_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_subprog_arg_info extends Struct {
    public bpf_arg_type arg_type;

    @InlineUnion(11854)
    public @Unsigned int mem_size;

    @InlineUnion(11854)
    public @Unsigned int btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_subprog_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_subprog_info extends Struct {
    public @Unsigned int start;

    public @Unsigned int linfo_idx;

    public @Unsigned short stack_depth;

    public @Unsigned short stack_extra;

    public short fastcall_stack_off;

    public boolean has_tail_call;

    public boolean tail_call_reachable;

    public boolean has_ld_abs;

    public boolean is_cb;

    public boolean is_async_cb;

    public boolean is_exception_cb;

    public boolean args_cached;

    public boolean keep_fastcall_stack;

    public boolean changes_pkt_data;

    public boolean might_sleep;

    public priv_stack_mode priv_stack_mode;

    public char arg_cnt;

    public bpf_subprog_arg_info @Size(5) [] args;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_id_pair"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_id_pair extends Struct {
    public @Unsigned int old;

    public @Unsigned int cur;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_idmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_idmap extends Struct {
    public @Unsigned int tmp_id_gen;

    public bpf_id_pair @Size(600) [] map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_idset"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_idset extends Struct {
    public @Unsigned int count;

    public @Unsigned int @Size(600) [] ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_scc_callchain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_scc_callchain extends Struct {
    public @Unsigned int @Size(7) [] callsites;

    public @Unsigned int scc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_scc_backedge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_scc_backedge extends Struct {
    public Ptr<bpf_scc_backedge> next;

    public bpf_verifier_state state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_scc_visit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_scc_visit extends Struct {
    public bpf_scc_callchain callchain;

    public Ptr<bpf_verifier_state> entry_state;

    public Ptr<bpf_scc_backedge> backedges;

    public @Unsigned int num_backedges;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_scc_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_scc_info extends Struct {
    public @Unsigned int num_visits;

    public bpf_scc_visit @Size(0) [] visits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_sched_ext_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_sched_ext_ops extends Struct {
    public bpf_struct_ops_common_value common;

    public sched_ext_ops data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union bpf_iter_link_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_link_info extends Union {
    public map_of_bpf_iter_link_info map;

    public cgroup_of_bpf_iter_link_info cgroup;

    public task_of_bpf_iter_link_info task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_iter_feature"
  )
  public enum bpf_iter_feature implements Enum<bpf_iter_feature>, TypedEnum<bpf_iter_feature, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_ITER_RESCHED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_ITER_RESCHED"
    )
    BPF_ITER_RESCHED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_reg extends Struct {
    public String target;

    public @OriginalName("bpf_iter_attach_target_t") Ptr<?> attach_target;

    public @OriginalName("bpf_iter_detach_target_t") Ptr<?> detach_target;

    public @OriginalName("bpf_iter_show_fdinfo_t") Ptr<?> show_fdinfo;

    public @OriginalName("bpf_iter_fill_link_info_t") Ptr<?> fill_link_info;

    public @OriginalName("bpf_iter_get_func_proto_t") Ptr<?> get_func_proto;

    public @Unsigned int ctx_arg_info_size;

    public @Unsigned int feature;

    public bpf_ctx_arg_aux @Size(2) [] ctx_arg_info;

    public Ptr<bpf_iter_seq_info> seq_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_meta extends Struct {
    @InlineUnion(13999)
    public Ptr<seq_file> seq;

    public @Unsigned long session_id;

    public @Unsigned long seq_num;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__ksym"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__ksym extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(14010)
    public Ptr<kallsym_iter> ksym;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cgroup_storage_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cgroup_storage_key extends Struct {
    public @Unsigned long cgroup_inode_id;

    public @Unsigned int attach_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cgroup_storage"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cgroup_storage extends Struct {
    @InlineUnion(14201)
    public Ptr<bpf_storage_buffer> buf;

    @InlineUnion(14201)
    public Ptr<?> percpu_buf;

    public Ptr<bpf_cgroup_storage_map> map;

    public bpf_cgroup_storage_key key;

    public list_head list_map;

    public list_head list_cg;

    public rb_node node;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_storage_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_storage_buffer extends Struct {
    public callback_head rcu;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage extends Struct {
    public Ptr<bpf_local_storage_data> @Size(16) [] cache;

    public Ptr<bpf_local_storage_map> smap;

    public hlist_head list;

    public Ptr<?> owner;

    public callback_head rcu;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_perf_event_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_perf_event_value extends Struct {
    public @Unsigned long counter;

    public @Unsigned long enabled;

    public @Unsigned long running;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_tracepoint_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_tracepoint_args extends Struct {
    public @Unsigned long @Size(0) [] args;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_task_fd_type"
  )
  public enum bpf_task_fd_type implements Enum<bpf_task_fd_type>, TypedEnum<bpf_task_fd_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_FD_TYPE_RAW_TRACEPOINT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_FD_TYPE_RAW_TRACEPOINT"
    )
    BPF_FD_TYPE_RAW_TRACEPOINT,

    /**
     * {@code BPF_FD_TYPE_TRACEPOINT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_FD_TYPE_TRACEPOINT"
    )
    BPF_FD_TYPE_TRACEPOINT,

    /**
     * {@code BPF_FD_TYPE_KPROBE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_FD_TYPE_KPROBE"
    )
    BPF_FD_TYPE_KPROBE,

    /**
     * {@code BPF_FD_TYPE_KRETPROBE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_FD_TYPE_KRETPROBE"
    )
    BPF_FD_TYPE_KRETPROBE,

    /**
     * {@code BPF_FD_TYPE_UPROBE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_FD_TYPE_UPROBE"
    )
    BPF_FD_TYPE_UPROBE,

    /**
     * {@code BPF_FD_TYPE_URETPROBE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_FD_TYPE_URETPROBE"
    )
    BPF_FD_TYPE_URETPROBE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dynptr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dynptr extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mem_alloc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mem_alloc extends Struct {
    public Ptr<bpf_mem_caches> caches;

    public Ptr<bpf_mem_cache> cache;

    public Ptr<obj_cgroup> objcg;

    public boolean percpu;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage_map extends Struct {
    public bpf_map map;

    public Ptr<bpf_local_storage_map_bucket> buckets;

    public @Unsigned int bucket_log;

    public @Unsigned short elem_size;

    public @Unsigned short cache_idx;

    public bpf_mem_alloc selem_ma;

    public bpf_mem_alloc storage_ma;

    public boolean bpf_ma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dynptr_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dynptr_kern extends Struct {
    public Ptr<?> data;

    public @Unsigned int size;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_link_primer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_link_primer extends Struct {
    public Ptr<bpf_link> link;

    public Ptr<file> file;

    public int fd;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_event_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_event_entry extends Struct {
    public Ptr<perf_event> event;

    public Ptr<file> perf_file;

    public Ptr<file> map_file;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_trace_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_trace_run_ctx extends Struct {
    public bpf_run_ctx run_ctx;

    public @Unsigned long bpf_cookie;

    public boolean is_uprobe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_key extends Struct {
    public Ptr<key> key;

    public boolean has_ref;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_perf_event_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_perf_event_data extends Struct {
    public @OriginalName("bpf_user_pt_regs_t") pt_regs regs;

    public @Unsigned long sample_period;

    public @Unsigned long addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_perf_event_data_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_perf_event_data_kern extends Struct {
    public Ptr<@OriginalName("bpf_user_pt_regs_t") pt_regs> regs;

    public Ptr<perf_sample_data> data;

    public Ptr<perf_event> event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage_map_bucket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage_map_bucket extends Struct {
    public hlist_head list;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage_data extends Struct {
    public Ptr<bpf_local_storage_map> smap;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_trace_module"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_trace_module extends Struct {
    public Ptr<module> module;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_trace_sample_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_trace_sample_data extends Struct {
    public perf_sample_data @Size(3) [] sds;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_nested_pt_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_nested_pt_regs extends Struct {
    public pt_regs @Size(3) [] regs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_tp_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_tp_regs extends Struct {
    public pt_regs @Size(3) [] regs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_session_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_session_run_ctx extends Struct {
    public bpf_run_ctx run_ctx;

    public boolean is_return;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kprobe_multi_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kprobe_multi_link extends Struct {
    public bpf_link link;

    public fprobe fp;

    public Ptr<java.lang. @Unsigned Long> addrs;

    public Ptr<java.lang. @Unsigned Long> cookies;

    public @Unsigned int cnt;

    public @Unsigned int mods_cnt;

    public Ptr<Ptr<module>> mods;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kprobe_multi_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kprobe_multi_run_ctx extends Struct {
    public bpf_session_run_ctx session_ctx;

    public Ptr<bpf_kprobe_multi_link> link;

    public @Unsigned long entry_ip;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_uprobe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_uprobe extends Struct {
    public Ptr<bpf_uprobe_multi_link> link;

    public @OriginalName("loff_t") long offset;

    public @Unsigned long ref_ctr_offset;

    public @Unsigned long cookie;

    public Ptr<uprobe> uprobe;

    public uprobe_consumer consumer;

    public boolean session;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_uprobe_multi_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_uprobe_multi_link extends Struct {
    public path path;

    public bpf_link link;

    public @Unsigned int cnt;

    public Ptr<bpf_uprobe> uprobes;

    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_uprobe_multi_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_uprobe_multi_run_ctx extends Struct {
    public bpf_session_run_ctx session_ctx;

    public @Unsigned long entry_ip;

    public Ptr<bpf_uprobe> uprobe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_stream_id"
  )
  public enum bpf_stream_id implements Enum<bpf_stream_id>, TypedEnum<bpf_stream_id, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_STDOUT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_STDOUT"
    )
    BPF_STDOUT,

    /**
     * {@code BPF_STDERR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_STDERR"
    )
    BPF_STDERR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stream_stage"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stream_stage extends Struct {
    public llist_head log;

    public int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_empty_prog_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_empty_prog_array extends Struct {
    public bpf_prog_array hdr;

    public Ptr<bpf_prog> null_prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_timed_may_goto"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_timed_may_goto extends Struct {
    public @Unsigned long count;

    public @Unsigned long timestamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_pack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_pack extends Struct {
    public list_head list;

    public Ptr<?> ptr;

    public @Unsigned long @Size(0) [] bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_dummy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_dummy extends Struct {
    public bpf_prog prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct _bpf_dtab_netdev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class _bpf_dtab_netdev extends Struct {
    public Ptr<net_device> dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_cmd"
  )
  public enum bpf_cmd implements Enum<bpf_cmd>, TypedEnum<bpf_cmd, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MAP_CREATE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_MAP_CREATE"
    )
    BPF_MAP_CREATE,

    /**
     * {@code BPF_MAP_LOOKUP_ELEM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_MAP_LOOKUP_ELEM"
    )
    BPF_MAP_LOOKUP_ELEM,

    /**
     * {@code BPF_MAP_UPDATE_ELEM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_MAP_UPDATE_ELEM"
    )
    BPF_MAP_UPDATE_ELEM,

    /**
     * {@code BPF_MAP_DELETE_ELEM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_MAP_DELETE_ELEM"
    )
    BPF_MAP_DELETE_ELEM,

    /**
     * {@code BPF_MAP_GET_NEXT_KEY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_MAP_GET_NEXT_KEY"
    )
    BPF_MAP_GET_NEXT_KEY,

    /**
     * {@code BPF_PROG_LOAD = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_PROG_LOAD"
    )
    BPF_PROG_LOAD,

    /**
     * {@code BPF_OBJ_PIN = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_OBJ_PIN"
    )
    BPF_OBJ_PIN,

    /**
     * {@code BPF_OBJ_GET = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_OBJ_GET"
    )
    BPF_OBJ_GET,

    /**
     * {@code BPF_PROG_ATTACH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_PROG_ATTACH"
    )
    BPF_PROG_ATTACH,

    /**
     * {@code BPF_PROG_DETACH = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_PROG_DETACH"
    )
    BPF_PROG_DETACH,

    /**
     * {@code BPF_PROG_TEST_RUN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_PROG_TEST_RUN"
    )
    BPF_PROG_TEST_RUN,

    /**
     * {@code BPF_PROG_RUN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_PROG_RUN"
    )
    BPF_PROG_RUN,

    /**
     * {@code BPF_PROG_GET_NEXT_ID = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_PROG_GET_NEXT_ID"
    )
    BPF_PROG_GET_NEXT_ID,

    /**
     * {@code BPF_MAP_GET_NEXT_ID = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_MAP_GET_NEXT_ID"
    )
    BPF_MAP_GET_NEXT_ID,

    /**
     * {@code BPF_PROG_GET_FD_BY_ID = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BPF_PROG_GET_FD_BY_ID"
    )
    BPF_PROG_GET_FD_BY_ID,

    /**
     * {@code BPF_MAP_GET_FD_BY_ID = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BPF_MAP_GET_FD_BY_ID"
    )
    BPF_MAP_GET_FD_BY_ID,

    /**
     * {@code BPF_OBJ_GET_INFO_BY_FD = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BPF_OBJ_GET_INFO_BY_FD"
    )
    BPF_OBJ_GET_INFO_BY_FD,

    /**
     * {@code BPF_PROG_QUERY = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BPF_PROG_QUERY"
    )
    BPF_PROG_QUERY,

    /**
     * {@code BPF_RAW_TRACEPOINT_OPEN = 17}
     */
    @EnumMember(
        value = 17L,
        name = "BPF_RAW_TRACEPOINT_OPEN"
    )
    BPF_RAW_TRACEPOINT_OPEN,

    /**
     * {@code BPF_BTF_LOAD = 18}
     */
    @EnumMember(
        value = 18L,
        name = "BPF_BTF_LOAD"
    )
    BPF_BTF_LOAD,

    /**
     * {@code BPF_BTF_GET_FD_BY_ID = 19}
     */
    @EnumMember(
        value = 19L,
        name = "BPF_BTF_GET_FD_BY_ID"
    )
    BPF_BTF_GET_FD_BY_ID,

    /**
     * {@code BPF_TASK_FD_QUERY = 20}
     */
    @EnumMember(
        value = 20L,
        name = "BPF_TASK_FD_QUERY"
    )
    BPF_TASK_FD_QUERY,

    /**
     * {@code BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21}
     */
    @EnumMember(
        value = 21L,
        name = "BPF_MAP_LOOKUP_AND_DELETE_ELEM"
    )
    BPF_MAP_LOOKUP_AND_DELETE_ELEM,

    /**
     * {@code BPF_MAP_FREEZE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "BPF_MAP_FREEZE"
    )
    BPF_MAP_FREEZE,

    /**
     * {@code BPF_BTF_GET_NEXT_ID = 23}
     */
    @EnumMember(
        value = 23L,
        name = "BPF_BTF_GET_NEXT_ID"
    )
    BPF_BTF_GET_NEXT_ID,

    /**
     * {@code BPF_MAP_LOOKUP_BATCH = 24}
     */
    @EnumMember(
        value = 24L,
        name = "BPF_MAP_LOOKUP_BATCH"
    )
    BPF_MAP_LOOKUP_BATCH,

    /**
     * {@code BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25}
     */
    @EnumMember(
        value = 25L,
        name = "BPF_MAP_LOOKUP_AND_DELETE_BATCH"
    )
    BPF_MAP_LOOKUP_AND_DELETE_BATCH,

    /**
     * {@code BPF_MAP_UPDATE_BATCH = 26}
     */
    @EnumMember(
        value = 26L,
        name = "BPF_MAP_UPDATE_BATCH"
    )
    BPF_MAP_UPDATE_BATCH,

    /**
     * {@code BPF_MAP_DELETE_BATCH = 27}
     */
    @EnumMember(
        value = 27L,
        name = "BPF_MAP_DELETE_BATCH"
    )
    BPF_MAP_DELETE_BATCH,

    /**
     * {@code BPF_LINK_CREATE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "BPF_LINK_CREATE"
    )
    BPF_LINK_CREATE,

    /**
     * {@code BPF_LINK_UPDATE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "BPF_LINK_UPDATE"
    )
    BPF_LINK_UPDATE,

    /**
     * {@code BPF_LINK_GET_FD_BY_ID = 30}
     */
    @EnumMember(
        value = 30L,
        name = "BPF_LINK_GET_FD_BY_ID"
    )
    BPF_LINK_GET_FD_BY_ID,

    /**
     * {@code BPF_LINK_GET_NEXT_ID = 31}
     */
    @EnumMember(
        value = 31L,
        name = "BPF_LINK_GET_NEXT_ID"
    )
    BPF_LINK_GET_NEXT_ID,

    /**
     * {@code BPF_ENABLE_STATS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "BPF_ENABLE_STATS"
    )
    BPF_ENABLE_STATS,

    /**
     * {@code BPF_ITER_CREATE = 33}
     */
    @EnumMember(
        value = 33L,
        name = "BPF_ITER_CREATE"
    )
    BPF_ITER_CREATE,

    /**
     * {@code BPF_LINK_DETACH = 34}
     */
    @EnumMember(
        value = 34L,
        name = "BPF_LINK_DETACH"
    )
    BPF_LINK_DETACH,

    /**
     * {@code BPF_PROG_BIND_MAP = 35}
     */
    @EnumMember(
        value = 35L,
        name = "BPF_PROG_BIND_MAP"
    )
    BPF_PROG_BIND_MAP,

    /**
     * {@code BPF_TOKEN_CREATE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "BPF_TOKEN_CREATE"
    )
    BPF_TOKEN_CREATE,

    /**
     * {@code BPF_PROG_STREAM_READ_BY_FD = 37}
     */
    @EnumMember(
        value = 37L,
        name = "BPF_PROG_STREAM_READ_BY_FD"
    )
    BPF_PROG_STREAM_READ_BY_FD,

    /**
     * {@code __MAX_BPF_CMD = 38}
     */
    @EnumMember(
        value = 38L,
        name = "__MAX_BPF_CMD"
    )
    __MAX_BPF_CMD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_perf_event_type"
  )
  public enum bpf_perf_event_type implements Enum<bpf_perf_event_type>, TypedEnum<bpf_perf_event_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_PERF_EVENT_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_PERF_EVENT_UNSPEC"
    )
    BPF_PERF_EVENT_UNSPEC,

    /**
     * {@code BPF_PERF_EVENT_UPROBE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_PERF_EVENT_UPROBE"
    )
    BPF_PERF_EVENT_UPROBE,

    /**
     * {@code BPF_PERF_EVENT_URETPROBE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_PERF_EVENT_URETPROBE"
    )
    BPF_PERF_EVENT_URETPROBE,

    /**
     * {@code BPF_PERF_EVENT_KPROBE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_PERF_EVENT_KPROBE"
    )
    BPF_PERF_EVENT_KPROBE,

    /**
     * {@code BPF_PERF_EVENT_KRETPROBE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_PERF_EVENT_KRETPROBE"
    )
    BPF_PERF_EVENT_KRETPROBE,

    /**
     * {@code BPF_PERF_EVENT_TRACEPOINT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_PERF_EVENT_TRACEPOINT"
    )
    BPF_PERF_EVENT_TRACEPOINT,

    /**
     * {@code BPF_PERF_EVENT_EVENT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_PERF_EVENT_EVENT"
    )
    BPF_PERF_EVENT_EVENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_stats_type"
  )
  public enum bpf_stats_type implements Enum<bpf_stats_type>, TypedEnum<bpf_stats_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_STATS_RUN_TIME = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_STATS_RUN_TIME"
    )
    BPF_STATS_RUN_TIME
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_info extends Struct {
    public @Unsigned int type;

    public @Unsigned int id;

    public char @Size(8) [] tag;

    public @Unsigned int jited_prog_len;

    public @Unsigned int xlated_prog_len;

    public @Unsigned long jited_prog_insns;

    public @Unsigned long xlated_prog_insns;

    public @Unsigned long load_time;

    public @Unsigned int created_by_uid;

    public @Unsigned int nr_map_ids;

    public @Unsigned long map_ids;

    public char @Size(16) [] name;

    public @Unsigned int ifindex;

    public @Unsigned int gpl_compatible;

    public @Unsigned long netns_dev;

    public @Unsigned long netns_ino;

    public @Unsigned int nr_jited_ksyms;

    public @Unsigned int nr_jited_func_lens;

    public @Unsigned long jited_ksyms;

    public @Unsigned long jited_func_lens;

    public @Unsigned int btf_id;

    public @Unsigned int func_info_rec_size;

    public @Unsigned long func_info;

    public @Unsigned int nr_func_info;

    public @Unsigned int nr_line_info;

    public @Unsigned long line_info;

    public @Unsigned long jited_line_info;

    public @Unsigned int nr_jited_line_info;

    public @Unsigned int line_info_rec_size;

    public @Unsigned int jited_line_info_rec_size;

    public @Unsigned int nr_prog_tags;

    public @Unsigned long prog_tags;

    public @Unsigned long run_time_ns;

    public @Unsigned long run_cnt;

    public @Unsigned long recursion_misses;

    public @Unsigned int verified_insns;

    public @Unsigned int attach_btf_obj_id;

    public @Unsigned int attach_btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_map_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_map_info extends Struct {
    public @Unsigned int type;

    public @Unsigned int id;

    public @Unsigned int key_size;

    public @Unsigned int value_size;

    public @Unsigned int max_entries;

    public @Unsigned int map_flags;

    public char @Size(16) [] name;

    public @Unsigned int ifindex;

    public @Unsigned int btf_vmlinux_value_type_id;

    public @Unsigned long netns_dev;

    public @Unsigned long netns_ino;

    public @Unsigned int btf_id;

    public @Unsigned int btf_key_type_id;

    public @Unsigned int btf_value_type_id;

    public @Unsigned int btf_vmlinux_id;

    public @Unsigned long map_extra;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_btf_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_btf_info extends Struct {
    public @Unsigned long btf;

    public @Unsigned int btf_size;

    public @Unsigned int id;

    public @Unsigned long name;

    public @Unsigned int name_len;

    public @Unsigned int kernel_btf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_token_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_token_info extends Struct {
    public @Unsigned long allowed_cmds;

    public @Unsigned long allowed_maps;

    public @Unsigned long allowed_progs;

    public @Unsigned long allowed_attachs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_spin_lock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_spin_lock extends Struct {
    public @Unsigned int val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_attach_target_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_attach_target_info extends Struct {
    public btf_func_model fmodel;

    public long tgt_addr;

    public Ptr<module> tgt_mod;

    public String tgt_name;

    public Ptr<btf_type> tgt_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tracing_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tracing_link extends Struct {
    public bpf_tramp_link link;

    public Ptr<bpf_trampoline> trampoline;

    public Ptr<bpf_prog> tgt_prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mprog_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mprog_entry extends Struct {
    public bpf_mprog_fp @Size(64) [] fp_items;

    public Ptr<bpf_mprog_bundle> parent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mprog_fp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mprog_fp extends Struct {
    public Ptr<bpf_prog> prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mprog_cp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mprog_cp extends Struct {
    public Ptr<bpf_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mprog_bundle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mprog_bundle extends Struct {
    public bpf_mprog_entry a;

    public bpf_mprog_entry b;

    public bpf_mprog_cp @Size(64) [] cp_items;

    public Ptr<bpf_prog> ref;

    public atomic64_t revision;

    public @Unsigned int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_audit"
  )
  public enum bpf_audit implements Enum<bpf_audit>, TypedEnum<bpf_audit, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_AUDIT_LOAD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_AUDIT_LOAD"
    )
    BPF_AUDIT_LOAD,

    /**
     * {@code BPF_AUDIT_UNLOAD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_AUDIT_UNLOAD"
    )
    BPF_AUDIT_UNLOAD,

    /**
     * {@code BPF_AUDIT_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_AUDIT_MAX"
    )
    BPF_AUDIT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_kstats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_kstats extends Struct {
    public @Unsigned long nsecs;

    public @Unsigned long cnt;

    public @Unsigned long misses;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_perf_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_perf_link extends Struct {
    public bpf_link link;

    public Ptr<file> perf_file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_cond_pseudo_jmp"
  )
  public enum bpf_cond_pseudo_jmp implements Enum<bpf_cond_pseudo_jmp>, TypedEnum<bpf_cond_pseudo_jmp, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MAY_GOTO = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_MAY_GOTO"
    )
    BPF_MAY_GOTO
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_flow_keys"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_flow_keys extends Struct {
    public @Unsigned short nhoff;

    public @Unsigned short thoff;

    public @Unsigned short addr_proto;

    public char is_frag;

    public char is_first_frag;

    public char is_encap;

    public char ip_proto;

    public @Unsigned @OriginalName("__be16") short n_proto;

    public @Unsigned @OriginalName("__be16") short sport;

    public @Unsigned @OriginalName("__be16") short dport;

    @InlineUnion(16866)
    public anon_member_of_anon_member_of_bpf_flow_keys anon10$0;

    @InlineUnion(16866)
    public anon_member_of_anon_member_of_bpf_flow_keys anon10$1;

    public @Unsigned int flags;

    public @Unsigned @OriginalName("__be32") int flow_label;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock extends Struct {
    public @Unsigned int bound_dev_if;

    public @Unsigned int family;

    public @Unsigned int type;

    public @Unsigned int protocol;

    public @Unsigned int mark;

    public @Unsigned int priority;

    public @Unsigned int src_ip4;

    public @Unsigned int @Size(4) [] src_ip6;

    public @Unsigned int src_port;

    public @Unsigned @OriginalName("__be16") short dst_port;

    public @Unsigned int dst_ip4;

    public @Unsigned int @Size(4) [] dst_ip6;

    public @Unsigned int state;

    public int rx_queue_mapping;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_core_relo_kind"
  )
  public enum bpf_core_relo_kind implements Enum<bpf_core_relo_kind>, TypedEnum<bpf_core_relo_kind, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_CORE_FIELD_BYTE_OFFSET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_CORE_FIELD_BYTE_OFFSET"
    )
    BPF_CORE_FIELD_BYTE_OFFSET,

    /**
     * {@code BPF_CORE_FIELD_BYTE_SIZE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_CORE_FIELD_BYTE_SIZE"
    )
    BPF_CORE_FIELD_BYTE_SIZE,

    /**
     * {@code BPF_CORE_FIELD_EXISTS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_CORE_FIELD_EXISTS"
    )
    BPF_CORE_FIELD_EXISTS,

    /**
     * {@code BPF_CORE_FIELD_SIGNED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_CORE_FIELD_SIGNED"
    )
    BPF_CORE_FIELD_SIGNED,

    /**
     * {@code BPF_CORE_FIELD_LSHIFT_U64 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_CORE_FIELD_LSHIFT_U64"
    )
    BPF_CORE_FIELD_LSHIFT_U64,

    /**
     * {@code BPF_CORE_FIELD_RSHIFT_U64 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BPF_CORE_FIELD_RSHIFT_U64"
    )
    BPF_CORE_FIELD_RSHIFT_U64,

    /**
     * {@code BPF_CORE_TYPE_ID_LOCAL = 6}
     */
    @EnumMember(
        value = 6L,
        name = "BPF_CORE_TYPE_ID_LOCAL"
    )
    BPF_CORE_TYPE_ID_LOCAL,

    /**
     * {@code BPF_CORE_TYPE_ID_TARGET = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_CORE_TYPE_ID_TARGET"
    )
    BPF_CORE_TYPE_ID_TARGET,

    /**
     * {@code BPF_CORE_TYPE_EXISTS = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BPF_CORE_TYPE_EXISTS"
    )
    BPF_CORE_TYPE_EXISTS,

    /**
     * {@code BPF_CORE_TYPE_SIZE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "BPF_CORE_TYPE_SIZE"
    )
    BPF_CORE_TYPE_SIZE,

    /**
     * {@code BPF_CORE_ENUMVAL_EXISTS = 10}
     */
    @EnumMember(
        value = 10L,
        name = "BPF_CORE_ENUMVAL_EXISTS"
    )
    BPF_CORE_ENUMVAL_EXISTS,

    /**
     * {@code BPF_CORE_ENUMVAL_VALUE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "BPF_CORE_ENUMVAL_VALUE"
    )
    BPF_CORE_ENUMVAL_VALUE,

    /**
     * {@code BPF_CORE_TYPE_MATCHES = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BPF_CORE_TYPE_MATCHES"
    )
    BPF_CORE_TYPE_MATCHES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_relo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_relo extends Struct {
    public @Unsigned int insn_off;

    public @Unsigned int type_id;

    public @Unsigned int access_str_off;

    public bpf_core_relo_kind kind;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kfunc_desc_tab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kfunc_desc_tab extends Struct {
    public bpf_kfunc_desc @Size(256) [] descs;

    public @Unsigned int nr_descs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kfunc_btf_tab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kfunc_btf_tab extends Struct {
    public bpf_kfunc_btf @Size(256) [] descs;

    public @Unsigned int nr_descs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_arg_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_arg_info extends Struct {
    public Ptr<bpf_ctx_arg_aux> info;

    public @Unsigned int cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_desc extends Struct {
    public Ptr<bpf_struct_ops> st_ops;

    public Ptr<btf_type> type;

    public Ptr<btf_type> value_type;

    public @Unsigned int type_id;

    public @Unsigned int value_id;

    public Ptr<bpf_struct_ops_arg_info> arg_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_ctx extends Struct {
    public Ptr<bpf_verifier_log> log;

    public Ptr<btf> btf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_stack_slot_type"
  )
  public enum bpf_stack_slot_type implements Enum<bpf_stack_slot_type>, TypedEnum<bpf_stack_slot_type, java.lang. @Unsigned Integer> {
    /**
     * {@code STACK_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "STACK_INVALID"
    )
    STACK_INVALID,

    /**
     * {@code STACK_SPILL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "STACK_SPILL"
    )
    STACK_SPILL,

    /**
     * {@code STACK_MISC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "STACK_MISC"
    )
    STACK_MISC,

    /**
     * {@code STACK_ZERO = 3}
     */
    @EnumMember(
        value = 3L,
        name = "STACK_ZERO"
    )
    STACK_ZERO,

    /**
     * {@code STACK_DYNPTR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "STACK_DYNPTR"
    )
    STACK_DYNPTR,

    /**
     * {@code STACK_ITER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "STACK_ITER"
    )
    STACK_ITER,

    /**
     * {@code STACK_IRQ_FLAG = 6}
     */
    @EnumMember(
        value = 6L,
        name = "STACK_IRQ_FLAG"
    )
    STACK_IRQ_FLAG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_state_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_state_list extends Struct {
    public bpf_verifier_state state;

    public list_head node;

    public @Unsigned int miss_cnt;

    public @Unsigned int hit_cnt;

    public @Unsigned int in_free_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_verifier_stack_elem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_verifier_stack_elem extends Struct {
    public bpf_verifier_state st;

    public int insn_idx;

    public int prev_insn_idx;

    public Ptr<bpf_verifier_stack_elem> next;

    public @Unsigned int log_pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_insn_cbs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_insn_cbs extends Struct {
    public @OriginalName("bpf_insn_print_t") Ptr<?> cb_print;

    public @OriginalName("bpf_insn_revmap_call_t") Ptr<?> cb_call;

    public @OriginalName("bpf_insn_print_imm_t") Ptr<?> cb_imm;

    public Ptr<?> private_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_features"
  )
  public enum bpf_features implements Enum<bpf_features>, TypedEnum<bpf_features, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_FEAT_RDONLY_CAST_TO_VOID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_FEAT_RDONLY_CAST_TO_VOID"
    )
    BPF_FEAT_RDONLY_CAST_TO_VOID,

    /**
     * {@code BPF_FEAT_STREAMS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_FEAT_STREAMS"
    )
    BPF_FEAT_STREAMS,

    /**
     * {@code __MAX_BPF_FEAT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__MAX_BPF_FEAT"
    )
    __MAX_BPF_FEAT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_call_arg_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_call_arg_meta extends Struct {
    public Ptr<bpf_map> map_ptr;

    public boolean raw_mode;

    public boolean pkt_access;

    public char release_regno;

    public int regno;

    public int access_size;

    public int mem_size;

    public @Unsigned long msize_max_value;

    public int ref_obj_id;

    public int dynptr_id;

    public int map_uid;

    public int func_id;

    public Ptr<btf> btf;

    public @Unsigned int btf_id;

    public Ptr<btf> ret_btf;

    public @Unsigned int ret_btf_id;

    public @Unsigned int subprogno;

    public Ptr<btf_field> kptr_field;

    public long const_map_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kfunc_call_arg_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kfunc_call_arg_meta extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int func_id;

    public @Unsigned int kfunc_flags;

    public Ptr<btf_type> func_proto;

    public String func_name;

    public @Unsigned int ref_obj_id;

    public char release_regno;

    public boolean r0_rdonly;

    public @Unsigned int ret_btf_id;

    public @Unsigned long r0_size;

    public @Unsigned int subprogno;

    public arg_constant_of_bpf_kfunc_call_arg_meta arg_constant;

    public Ptr<btf> arg_btf;

    public @Unsigned int arg_btf_id;

    public boolean arg_owning_ref;

    public boolean arg_prog;

    public arg_list_head_of_bpf_kfunc_call_arg_meta_and_arg_rbtree_root_of_bpf_kfunc_call_arg_meta arg_list_head;

    public arg_list_head_of_bpf_kfunc_call_arg_meta_and_arg_rbtree_root_of_bpf_kfunc_call_arg_meta arg_rbtree_root;

    public initialized_dynptr_of_bpf_kfunc_call_arg_meta initialized_dynptr;

    public iter_of_bpf_kfunc_call_arg_meta iter;

    public map_of_bpf_kfunc_call_arg_meta map;

    public @Unsigned long mem_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kfunc_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kfunc_desc extends Struct {
    public btf_func_model func_model;

    public @Unsigned int func_id;

    public int imm;

    public @Unsigned short offset;

    public @Unsigned long addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_kfunc_btf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_kfunc_btf extends Struct {
    public Ptr<btf> btf;

    public Ptr<module> module;

    public @Unsigned short offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_access_src"
  )
  public enum bpf_access_src implements Enum<bpf_access_src>, TypedEnum<bpf_access_src, java.lang. @Unsigned Integer> {
    /**
     * {@code ACCESS_DIRECT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ACCESS_DIRECT"
    )
    ACCESS_DIRECT,

    /**
     * {@code ACCESS_HELPER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ACCESS_HELPER"
    )
    ACCESS_HELPER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_meta__safe_trusted"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_meta__safe_trusted extends Struct {
    public Ptr<seq_file> seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__task__safe_trusted"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__task__safe_trusted extends Struct {
    public Ptr<bpf_iter_meta> meta;

    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_reg_types"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_reg_types extends Struct {
    public bpf_reg_type @Size(10) [] types;

    public Ptr<java.lang. @Unsigned Integer> btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sanitize_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sanitize_info extends Struct {
    public bpf_insn_aux_data aux;

    public boolean mask_to_left;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mount_opts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mount_opts extends Struct {
    public kuid_t uid;

    public kgid_t gid;

    public @Unsigned @OriginalName("umode_t") short mode;

    public @Unsigned long delegate_cmds;

    public @Unsigned long delegate_maps;

    public @Unsigned long delegate_progs;

    public @Unsigned long delegate_attachs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_preload_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_preload_info extends Struct {
    public char @Size(16) [] link_name;

    public Ptr<bpf_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_preload_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_preload_ops extends Struct {
    public Ptr<?> preload;

    public Ptr<module> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_type"
  )
  public enum bpf_type implements Enum<bpf_type>, TypedEnum<bpf_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_TYPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_TYPE_UNSPEC"
    )
    BPF_TYPE_UNSPEC,

    /**
     * {@code BPF_TYPE_PROG = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_TYPE_PROG"
    )
    BPF_TYPE_PROG,

    /**
     * {@code BPF_TYPE_MAP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_TYPE_MAP"
    )
    BPF_TYPE_MAP,

    /**
     * {@code BPF_TYPE_LINK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_TYPE_LINK"
    )
    BPF_TYPE_LINK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_timer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_timer extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_wq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_wq extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_list_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_list_head extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_list_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_list_node extends Struct {
    public @Unsigned long @Size(3) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_rb_root"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_rb_root extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_rb_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_rb_node extends Struct {
    public @Unsigned long @Size(4) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_refcount"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_refcount extends Struct {
    public @Unsigned int @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_pidns_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_pidns_info extends Struct {
    public @Unsigned int pid;

    public @Unsigned int tgid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_kfunc_flags"
  )
  public enum bpf_kfunc_flags implements Enum<bpf_kfunc_flags>, TypedEnum<bpf_kfunc_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_F_PAD_ZEROS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_F_PAD_ZEROS"
    )
    BPF_F_PAD_ZEROS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_rb_node_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_rb_node_kern extends Struct {
    public rb_node rb_node;

    public Ptr<?> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_list_node_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_list_node_kern extends Struct {
    public list_head list_head;

    public Ptr<?> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_bprintf_buffers"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_bprintf_buffers extends Struct {
    public char @Size(512) [] bin_args;

    public char @Size(1024) [] buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_async_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_async_cb extends Struct {
    public Ptr<bpf_map> map;

    public Ptr<bpf_prog> prog;

    public Ptr<?> callback_fn;

    public Ptr<?> value;

    @InlineUnion(17131)
    public callback_head rcu;

    @InlineUnion(17131)
    public work_struct delete_work;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_hrtimer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_hrtimer extends Struct {
    public bpf_async_cb cb;

    public hrtimer timer;

    public atomic_t cancelling;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_work extends Struct {
    public bpf_async_cb cb;

    public work_struct work;

    public work_struct delete_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_async_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_async_kern extends Struct {
    @InlineUnion(17135)
    public Ptr<bpf_async_cb> cb;

    @InlineUnion(17135)
    public Ptr<bpf_hrtimer> timer;

    @InlineUnion(17135)
    public Ptr<bpf_work> work;

    public bpf_spin_lock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_async_type"
  )
  public enum bpf_async_type implements Enum<bpf_async_type>, TypedEnum<bpf_async_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_ASYNC_TYPE_TIMER = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_ASYNC_TYPE_TIMER"
    )
    BPF_ASYNC_TYPE_TIMER,

    /**
     * {@code BPF_ASYNC_TYPE_WQ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_ASYNC_TYPE_WQ"
    )
    BPF_ASYNC_TYPE_WQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_throw_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_throw_ctx extends Struct {
    public Ptr<bpf_prog_aux> aux;

    public @Unsigned long sp;

    public @Unsigned long bp;

    public int cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_bits"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_bits extends Struct {
    public @Unsigned long @Size(2) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_bits_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_bits_kern extends Struct {
    @InlineUnion(17174)
    public Ptr<java.lang. @Unsigned Long> bits;

    @InlineUnion(17174)
    public @Unsigned long bits_copy;

    public int nr_bits;

    public int bit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_num"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_num extends Struct {
    public @Unsigned long @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_target_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_target_info extends Struct {
    public list_head list;

    public Ptr<bpf_iter_reg> reg_info;

    public @Unsigned int btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_link extends Struct {
    public bpf_link link;

    public bpf_iter_aux_info aux;

    public Ptr<bpf_iter_target_info> tinfo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_priv_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_priv_data extends Struct {
    public Ptr<bpf_iter_target_info> tinfo;

    public Ptr<bpf_iter_seq_info> seq_info;

    public Ptr<bpf_prog> prog;

    public @Unsigned long session_id;

    public @Unsigned long seq_num;

    public boolean done_stop;

    public char @Size(0) [] target_private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_num_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_num_kern extends Struct {
    public int cur;

    public int end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_map_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_map_info extends Struct {
    public @Unsigned int map_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__bpf_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__bpf_map extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17232)
    public Ptr<bpf_map> map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_task_common"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_task_common extends Struct {
    public Ptr<pid_namespace> ns;

    public bpf_iter_task_type type;

    public @Unsigned int pid;

    public @Unsigned int pid_visiting;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_task_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_task_info extends Struct {
    public bpf_iter_seq_task_common common;

    public @Unsigned int tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__task extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17238)
    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_task_file_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_task_file_info extends Struct {
    public bpf_iter_seq_task_common common;

    public Ptr<task_struct> task;

    public @Unsigned int tid;

    public @Unsigned int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__task_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__task_file extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17238)
    public Ptr<task_struct> task;

    public @Unsigned int fd;

    @InlineUnion(17241)
    public Ptr<file> file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_task_vma_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_task_vma_info extends Struct {
    public bpf_iter_seq_task_common common;

    public Ptr<task_struct> task;

    public Ptr<mm_struct> mm;

    public Ptr<vm_area_struct> vma;

    public @Unsigned int tid;

    public @Unsigned long prev_vm_start;

    public @Unsigned long prev_vm_end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_task_vma_iter_find_op"
  )
  public enum bpf_task_vma_iter_find_op implements Enum<bpf_task_vma_iter_find_op>, TypedEnum<bpf_task_vma_iter_find_op, java.lang. @Unsigned Integer> {
    /**
     * {@code task_vma_iter_first_vma = 0}
     */
    @EnumMember(
        value = 0L,
        name = "task_vma_iter_first_vma"
    )
    task_vma_iter_first_vma,

    /**
     * {@code task_vma_iter_next_vma = 1}
     */
    @EnumMember(
        value = 1L,
        name = "task_vma_iter_next_vma"
    )
    task_vma_iter_next_vma,

    /**
     * {@code task_vma_iter_find_vma = 2}
     */
    @EnumMember(
        value = 2L,
        name = "task_vma_iter_find_vma"
    )
    task_vma_iter_find_vma
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__task_vma"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__task_vma extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17238)
    public Ptr<task_struct> task;

    @InlineUnion(17245)
    public Ptr<vm_area_struct> vma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_task_vma_kern_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_task_vma_kern_data extends Struct {
    public Ptr<task_struct> task;

    public Ptr<mm_struct> mm;

    public Ptr<mmap_unlock_irq_work> work;

    public vma_iterator vmi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_task_vma"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_task_vma extends Struct {
    public @Unsigned long @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_task_vma_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_task_vma_kern extends Struct {
    public Ptr<bpf_iter_task_vma_kern_data> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_css_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_css_task extends Struct {
    public @Unsigned long @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_css_task_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_css_task_kern extends Struct {
    public Ptr<css_task_iter> css_it;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_task extends Struct {
    public @Unsigned long @Size(3) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_task_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_task_kern extends Struct {
    public Ptr<task_struct> task;

    public Ptr<task_struct> pos;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_prog_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_prog_info extends Struct {
    public @Unsigned int prog_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__bpf_prog"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__bpf_prog extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17273)
    public Ptr<bpf_prog> prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_link_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_link_info extends Struct {
    public @Unsigned int link_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__bpf_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__bpf_link extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17277)
    public Ptr<bpf_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__bpf_map_elem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__bpf_map_elem extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17232)
    public Ptr<bpf_map> map;

    @InlineUnion(17283)
    public Ptr<?> key;

    @InlineUnion(17284)
    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lru_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lru_node extends Struct {
    public list_head list;

    public @Unsigned short cpu;

    public char type;

    public char ref;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lru_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lru_list extends Struct {
    public list_head @Size(3) [] lists;

    public @Unsigned int @Size(2) [] counts;

    public Ptr<list_head> next_inactive_rotation;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lru_locallist"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lru_locallist extends Struct {
    public list_head @Size(2) [] lists;

    public @Unsigned short next_steal;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_common_lru"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_common_lru extends Struct {
    public bpf_lru_list lru_list;

    public Ptr<bpf_lru_locallist> local_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lru"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lru extends Struct {
    @InlineUnion(17301)
    public bpf_common_lru common_lru;

    @InlineUnion(17301)
    public Ptr<bpf_lru_list> percpu_lru;

    public @OriginalName("del_from_htab_func") Ptr<?> del_from_htab;

    public Ptr<?> del_arg;

    public @Unsigned int hash_offset;

    public @Unsigned int target_free;

    public @Unsigned int nr_scans;

    public boolean percpu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_htab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_htab extends Struct {
    public bpf_map map;

    public bpf_mem_alloc ma;

    public bpf_mem_alloc pcpu_ma;

    public Ptr<bucket> buckets;

    public Ptr<?> elems;

    @InlineUnion(17305)
    public pcpu_freelist freelist;

    @InlineUnion(17305)
    public bpf_lru lru;

    public Ptr<Ptr<htab_elem>> extra_elems;

    public percpu_counter pcount;

    public atomic_t count;

    public boolean use_percpu_counter;

    public @Unsigned int n_buckets;

    public @Unsigned int elem_size;

    public @Unsigned int hashrnd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_hash_map_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_hash_map_info extends Struct {
    public Ptr<bpf_map> map;

    public Ptr<bpf_htab> htab;

    public Ptr<?> percpu_value_buf;

    public @Unsigned int bucket_id;

    public @Unsigned int skip_elems;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_array_map_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_array_map_info extends Struct {
    public Ptr<bpf_map> map;

    public Ptr<?> percpu_value_buf;

    public @Unsigned int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_lru_list_type"
  )
  public enum bpf_lru_list_type implements Enum<bpf_lru_list_type>, TypedEnum<bpf_lru_list_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_LRU_LIST_T_ACTIVE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_LRU_LIST_T_ACTIVE"
    )
    BPF_LRU_LIST_T_ACTIVE,

    /**
     * {@code BPF_LRU_LIST_T_INACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_LRU_LIST_T_INACTIVE"
    )
    BPF_LRU_LIST_T_INACTIVE,

    /**
     * {@code BPF_LRU_LIST_T_FREE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_LRU_LIST_T_FREE"
    )
    BPF_LRU_LIST_T_FREE,

    /**
     * {@code BPF_LRU_LOCAL_LIST_T_FREE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BPF_LRU_LOCAL_LIST_T_FREE"
    )
    BPF_LRU_LOCAL_LIST_T_FREE,

    /**
     * {@code BPF_LRU_LOCAL_LIST_T_PENDING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BPF_LRU_LOCAL_LIST_T_PENDING"
    )
    BPF_LRU_LOCAL_LIST_T_PENDING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lpm_trie_key_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lpm_trie_key_hdr extends Struct {
    public @Unsigned int prefixlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lpm_trie_key_u8"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lpm_trie_key_u8 extends Struct {
    @InlineUnion(17335)
    public bpf_lpm_trie_key_hdr hdr;

    @InlineUnion(17335)
    public @Unsigned int prefixlen;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_bloom_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_bloom_filter extends Struct {
    public bpf_map map;

    public @Unsigned int bitset_mask;

    public @Unsigned int hash_seed;

    public @Unsigned int nr_hash_funcs;

    public @Unsigned long @Size(0) [] bitset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cgroup_storage_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cgroup_storage_map extends Struct {
    public bpf_map map;

    public @OriginalName("spinlock_t") spinlock lock;

    public rb_root root;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_queue_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_queue_stack extends Struct {
    public bpf_map map;

    public @OriginalName("rqspinlock_t") qspinlock lock;

    public @Unsigned int head;

    public @Unsigned int tail;

    public @Unsigned int size;

    public char @Size(0) [] elements;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ringbuf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ringbuf extends Struct {
    public @OriginalName("wait_queue_head_t") wait_queue_head waitq;

    public irq_work work;

    public @Unsigned long mask;

    public Ptr<Ptr<page>> pages;

    public int nr_pages;

    public @OriginalName("rqspinlock_t") qspinlock spinlock;

    public atomic_t busy;

    public @Unsigned long consumer_pos;

    public @Unsigned long producer_pos;

    public @Unsigned long pending_pos;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ringbuf_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ringbuf_map extends Struct {
    public bpf_map map;

    public Ptr<bpf_ringbuf> rb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ringbuf_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ringbuf_hdr extends Struct {
    public @Unsigned int len;

    public @Unsigned int pg_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage_elem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage_elem extends Struct {
    public hlist_node map_node;

    public hlist_node snode;

    public Ptr<bpf_local_storage> local_storage;

    @InlineUnion(17395)
    public callback_head rcu;

    @InlineUnion(17395)
    public hlist_node free_node;

    public bpf_local_storage_data sdata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_local_storage_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_local_storage_cache extends Struct {
    public @OriginalName("spinlock_t") spinlock idx_lock;

    public @Unsigned long @Size(16) [] idx_usage_counts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_storage_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_storage_blob extends Struct {
    public Ptr<bpf_local_storage> storage;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tuple"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tuple extends Struct {
    public Ptr<bpf_prog> prog;

    public Ptr<bpf_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_shim_tramp_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_shim_tramp_link extends Struct {
    public bpf_tramp_link link;

    public Ptr<bpf_trampoline> trampoline;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock_addr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock_addr extends Struct {
    public @Unsigned int user_family;

    public @Unsigned int user_ip4;

    public @Unsigned int @Size(4) [] user_ip6;

    public @Unsigned int user_port;

    public @Unsigned int family;

    public @Unsigned int type;

    public @Unsigned int protocol;

    public @Unsigned int msg_src_ip4;

    public @Unsigned int @Size(4) [] msg_src_ip6;

    @InlineUnion(16859)
    public Ptr<bpf_sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock_ops extends Struct {
    public @Unsigned int op;

    @InlineUnion(17459)
    public @Unsigned int @Size(4) [] args;

    @InlineUnion(17459)
    public @Unsigned int reply;

    @InlineUnion(17459)
    public @Unsigned int @Size(4) [] replylong;

    public @Unsigned int family;

    public @Unsigned int remote_ip4;

    public @Unsigned int local_ip4;

    public @Unsigned int @Size(4) [] remote_ip6;

    public @Unsigned int @Size(4) [] local_ip6;

    public @Unsigned int remote_port;

    public @Unsigned int local_port;

    public @Unsigned int is_fullsock;

    public @Unsigned int snd_cwnd;

    public @Unsigned int srtt_us;

    public @Unsigned int bpf_sock_ops_cb_flags;

    public @Unsigned int state;

    public @Unsigned int rtt_min;

    public @Unsigned int snd_ssthresh;

    public @Unsigned int rcv_nxt;

    public @Unsigned int snd_nxt;

    public @Unsigned int snd_una;

    public @Unsigned int mss_cache;

    public @Unsigned int ecn_flags;

    public @Unsigned int rate_delivered;

    public @Unsigned int rate_interval_us;

    public @Unsigned int packets_out;

    public @Unsigned int retrans_out;

    public @Unsigned int total_retrans;

    public @Unsigned int segs_in;

    public @Unsigned int data_segs_in;

    public @Unsigned int segs_out;

    public @Unsigned int data_segs_out;

    public @Unsigned int lost_out;

    public @Unsigned int sacked_out;

    public @Unsigned int sk_txhash;

    public @Unsigned long bytes_received;

    public @Unsigned long bytes_acked;

    @InlineUnion(16859)
    public Ptr<bpf_sock> sk;

    @InlineUnion(17460)
    public Ptr<?> skb_data;

    @InlineUnion(17461)
    public Ptr<?> skb_data_end;

    public @Unsigned int skb_len;

    public @Unsigned int skb_tcp_flags;

    public @Unsigned long skb_hwtstamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cgroup_dev_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cgroup_dev_ctx extends Struct {
    public @Unsigned int access_type;

    public @Unsigned int major;

    public @Unsigned int minor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sysctl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sysctl extends Struct {
    public @Unsigned int write;

    public @Unsigned int file_pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sockopt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sockopt extends Struct {
    @InlineUnion(16859)
    public Ptr<bpf_sock> sk;

    @InlineUnion(17465)
    public Ptr<?> optval;

    @InlineUnion(17466)
    public Ptr<?> optval_end;

    public int level;

    public int optname;

    public int optlen;

    public int retval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sk_lookup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sk_lookup extends Struct {
    @InlineUnion(17468)
    public anon_member_of___sk_buff_and_anon_member_of_anon_member_of_bpf_sk_lookup_and_anon_member_of_bpf_sock_addr anon0$0;

    @InlineUnion(17468)
    public @Unsigned long cookie;

    public @Unsigned int family;

    public @Unsigned int protocol;

    public @Unsigned int remote_ip4;

    public @Unsigned int @Size(4) [] remote_ip6;

    public @Unsigned @OriginalName("__be16") short remote_port;

    public @Unsigned int local_ip4;

    public @Unsigned int @Size(4) [] local_ip6;

    public @Unsigned int local_port;

    public @Unsigned int ingress_ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_flow_dissector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_flow_dissector extends Struct {
    public Ptr<bpf_flow_keys> flow_keys;

    public Ptr<sk_buff> skb;

    public Ptr<?> data;

    public Ptr<?> data_end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock_addr_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock_addr_kern extends Struct {
    public Ptr<sock> sk;

    public Ptr<sockaddr> uaddr;

    public @Unsigned long tmp_reg;

    public Ptr<?> t_ctx;

    public @Unsigned int uaddrlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock_ops_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock_ops_kern extends Struct {
    public Ptr<sock> sk;

    @InlineUnion(17512)
    public @Unsigned int @Size(4) [] args;

    @InlineUnion(17512)
    public @Unsigned int reply;

    @InlineUnion(17512)
    public @Unsigned int @Size(4) [] replylong;

    public Ptr<sk_buff> syn_skb;

    public Ptr<sk_buff> skb;

    public Ptr<?> skb_data_end;

    public char op;

    public char is_fullsock;

    public char is_locked_tcp_sock;

    public char remaining_opt_len;

    public @Unsigned long temp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sysctl_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sysctl_kern extends Struct {
    public Ptr<ctl_table_header> head;

    public Ptr<ctl_table> table;

    public Ptr<?> cur_val;

    public @Unsigned long cur_len;

    public Ptr<?> new_val;

    public @Unsigned long new_len;

    public int new_updated;

    public int write;

    public Ptr<java.lang. @OriginalName("loff_t") Long> ppos;

    public @Unsigned long tmp_reg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sockopt_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sockopt_kern extends Struct {
    public Ptr<sock> sk;

    public Ptr<java.lang.Character> optval;

    public Ptr<java.lang.Character> optval_end;

    public int level;

    public int optname;

    public int optlen;

    public Ptr<task_struct> current_task;

    public @Unsigned long tmp_reg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sk_lookup_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sk_lookup_kern extends Struct {
    public @Unsigned short family;

    public @Unsigned short protocol;

    public @Unsigned @OriginalName("__be16") short sport;

    public @Unsigned short dport;

    public addrs_of_anon_member_of_iphdr_and_anon_member_of_anon_member_of_iphdr_and_v4_of_bpf_sk_lookup_kern v4;

    public v6_of_bpf_sk_lookup_kern v6;

    public Ptr<sock> selected_sk;

    public @Unsigned int ingress_ifindex;

    public boolean no_reuseport;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_nf_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_nf_ctx extends Struct {
    public Ptr<nf_hook_state> state;

    public Ptr<sk_buff> skb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_cand"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_cand extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_cand_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_cand_list extends Struct {
    public Ptr<bpf_core_cand> cands;

    public int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_accessor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_accessor extends Struct {
    public @Unsigned int type_id;

    public @Unsigned int idx;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_spec extends Struct {
    public Ptr<btf> btf;

    public bpf_core_accessor @Size(64) [] spec;

    public @Unsigned int root_type_id;

    public bpf_core_relo_kind relo_kind;

    public int len;

    public int @Size(64) [] raw_spec;

    public int raw_len;

    public @Unsigned int bit_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_core_relo_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_core_relo_res extends Struct {
    public @Unsigned long orig_val;

    public @Unsigned long new_val;

    public boolean poison;

    public boolean validate;

    public boolean fail_memsz_adjust;

    public @Unsigned int orig_sz;

    public @Unsigned int orig_type_id;

    public @Unsigned int new_sz;

    public @Unsigned int new_type_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_ctx_convert"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_ctx_convert extends Struct {
    public __sk_buff BPF_PROG_TYPE_SOCKET_FILTER_prog;

    public sk_buff BPF_PROG_TYPE_SOCKET_FILTER_kern;

    public __sk_buff BPF_PROG_TYPE_SCHED_CLS_prog;

    public sk_buff BPF_PROG_TYPE_SCHED_CLS_kern;

    public __sk_buff BPF_PROG_TYPE_SCHED_ACT_prog;

    public sk_buff BPF_PROG_TYPE_SCHED_ACT_kern;

    public xdp_md BPF_PROG_TYPE_XDP_prog;

    public xdp_buff BPF_PROG_TYPE_XDP_kern;

    public __sk_buff BPF_PROG_TYPE_CGROUP_SKB_prog;

    public sk_buff BPF_PROG_TYPE_CGROUP_SKB_kern;

    public bpf_sock BPF_PROG_TYPE_CGROUP_SOCK_prog;

    public sock BPF_PROG_TYPE_CGROUP_SOCK_kern;

    public bpf_sock_addr BPF_PROG_TYPE_CGROUP_SOCK_ADDR_prog;

    public bpf_sock_addr_kern BPF_PROG_TYPE_CGROUP_SOCK_ADDR_kern;

    public __sk_buff BPF_PROG_TYPE_LWT_IN_prog;

    public sk_buff BPF_PROG_TYPE_LWT_IN_kern;

    public __sk_buff BPF_PROG_TYPE_LWT_OUT_prog;

    public sk_buff BPF_PROG_TYPE_LWT_OUT_kern;

    public __sk_buff BPF_PROG_TYPE_LWT_XMIT_prog;

    public sk_buff BPF_PROG_TYPE_LWT_XMIT_kern;

    public __sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_prog;

    public sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_kern;

    public bpf_sock_ops BPF_PROG_TYPE_SOCK_OPS_prog;

    public bpf_sock_ops_kern BPF_PROG_TYPE_SOCK_OPS_kern;

    public __sk_buff BPF_PROG_TYPE_SK_SKB_prog;

    public sk_buff BPF_PROG_TYPE_SK_SKB_kern;

    public sk_msg_md BPF_PROG_TYPE_SK_MSG_prog;

    public sk_msg BPF_PROG_TYPE_SK_MSG_kern;

    public __sk_buff BPF_PROG_TYPE_FLOW_DISSECTOR_prog;

    public bpf_flow_dissector BPF_PROG_TYPE_FLOW_DISSECTOR_kern;

    public @OriginalName("bpf_user_pt_regs_t") pt_regs BPF_PROG_TYPE_KPROBE_prog;

    public pt_regs BPF_PROG_TYPE_KPROBE_kern;

    public @Unsigned long BPF_PROG_TYPE_TRACEPOINT_prog;

    public @Unsigned long BPF_PROG_TYPE_TRACEPOINT_kern;

    public bpf_perf_event_data BPF_PROG_TYPE_PERF_EVENT_prog;

    public bpf_perf_event_data_kern BPF_PROG_TYPE_PERF_EVENT_kern;

    public bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_prog;

    public @Unsigned long BPF_PROG_TYPE_RAW_TRACEPOINT_kern;

    public bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_prog;

    public @Unsigned long BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_kern;

    public Ptr<?> BPF_PROG_TYPE_TRACING_prog;

    public Ptr<?> BPF_PROG_TYPE_TRACING_kern;

    public bpf_cgroup_dev_ctx BPF_PROG_TYPE_CGROUP_DEVICE_prog;

    public bpf_cgroup_dev_ctx BPF_PROG_TYPE_CGROUP_DEVICE_kern;

    public bpf_sysctl BPF_PROG_TYPE_CGROUP_SYSCTL_prog;

    public bpf_sysctl_kern BPF_PROG_TYPE_CGROUP_SYSCTL_kern;

    public bpf_sockopt BPF_PROG_TYPE_CGROUP_SOCKOPT_prog;

    public bpf_sockopt_kern BPF_PROG_TYPE_CGROUP_SOCKOPT_kern;

    public sk_reuseport_md BPF_PROG_TYPE_SK_REUSEPORT_prog;

    public sk_reuseport_kern BPF_PROG_TYPE_SK_REUSEPORT_kern;

    public bpf_sk_lookup BPF_PROG_TYPE_SK_LOOKUP_prog;

    public bpf_sk_lookup_kern BPF_PROG_TYPE_SK_LOOKUP_kern;

    public Ptr<?> BPF_PROG_TYPE_STRUCT_OPS_prog;

    public Ptr<?> BPF_PROG_TYPE_STRUCT_OPS_kern;

    public Ptr<?> BPF_PROG_TYPE_EXT_prog;

    public Ptr<?> BPF_PROG_TYPE_EXT_kern;

    public Ptr<?> BPF_PROG_TYPE_LSM_prog;

    public Ptr<?> BPF_PROG_TYPE_LSM_kern;

    public Ptr<?> BPF_PROG_TYPE_SYSCALL_prog;

    public Ptr<?> BPF_PROG_TYPE_SYSCALL_kern;

    public bpf_nf_ctx BPF_PROG_TYPE_NETFILTER_prog;

    public bpf_nf_ctx BPF_PROG_TYPE_NETFILTER_kern;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_tp_null_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_tp_null_args extends Struct {
    public String func;

    public @Unsigned long mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_struct_walk_result"
  )
  public enum bpf_struct_walk_result implements Enum<bpf_struct_walk_result>, TypedEnum<bpf_struct_walk_result, java.lang. @Unsigned Integer> {
    /**
     * {@code WALK_SCALAR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "WALK_SCALAR"
    )
    WALK_SCALAR,

    /**
     * {@code WALK_PTR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "WALK_PTR"
    )
    WALK_PTR,

    /**
     * {@code WALK_PTR_UNTRUSTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "WALK_PTR_UNTRUSTED"
    )
    WALK_PTR_UNTRUSTED,

    /**
     * {@code WALK_STRUCT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "WALK_STRUCT"
    )
    WALK_STRUCT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cand_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cand_cache extends Struct {
    public String name;

    public @Unsigned int name_len;

    public @Unsigned short kind;

    public @Unsigned short cnt;

    public AnonymousType394349340C48 @Size(0) [] cands;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mem_caches"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mem_caches extends Struct {
    public bpf_mem_cache @Size(11) [] cache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_mem_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_mem_cache extends Struct {
    public llist_head free_llist;

    public local_t active;

    public llist_head free_llist_extra;

    public irq_work refill_work;

    public Ptr<obj_cgroup> objcg;

    public int unit_size;

    public int free_cnt;

    public int low_watermark;

    public int high_watermark;

    public int batch;

    public int percpu_size;

    public boolean draining;

    public Ptr<bpf_mem_cache> tgt;

    public llist_head free_by_rcu;

    public Ptr<llist_node> free_by_rcu_tail;

    public llist_head waiting_for_gp;

    public Ptr<llist_node> waiting_for_gp_tail;

    public callback_head rcu;

    public atomic_t call_rcu_in_progress;

    public llist_head free_llist_extra_rcu;

    public llist_head free_by_rcu_ttrace;

    public llist_head waiting_for_gp_ttrace;

    public callback_head rcu_ttrace;

    public atomic_t call_rcu_ttrace_in_progress;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_res_spin_lock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_res_spin_lock extends Struct {
    public @Unsigned int val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stream_elem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stream_elem extends Struct {
    public llist_node node;

    public int total_len;

    public int consumed_len;

    public char @Size(0) [] str;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stream_page"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stream_page extends Struct {
    public @OriginalName("refcount_t") refcount_struct ref;

    public @Unsigned int consumed;

    public char @Size(0) [] buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_arena"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_arena extends Struct {
    public bpf_map map;

    public @Unsigned long user_vm_start;

    public @Unsigned long user_vm_end;

    public Ptr<vm_struct> kern_vm;

    public range_tree rt;

    public list_head vma_list;

    public mutex lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dispatcher_prog"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dispatcher_prog extends Struct {
    public Ptr<bpf_prog> prog;

    public @OriginalName("refcount_t") refcount_struct users;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dispatcher"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dispatcher extends Struct {
    public mutex mutex;

    public Ptr<?> func;

    public bpf_dispatcher_prog @Size(48) [] progs;

    public int num_progs;

    public Ptr<?> image;

    public Ptr<?> rw_image;

    public @Unsigned int image_off;

    public bpf_ksym ksym;

    public Ptr<static_call_key> sc_key;

    public Ptr<?> sc_tramp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int fd; unsigned int id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_of_bpf_cpumap_val_and_bpf_prog_of_bpf_devmap_val extends Union {
    public int fd;

    public @Unsigned int id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_devmap_val"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_devmap_val extends Struct {
    public @Unsigned int ifindex;

    public bpf_prog_of_bpf_cpumap_val_and_bpf_prog_of_bpf_devmap_val bpf_prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dtab_netdev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dtab_netdev extends Struct {
    public Ptr<net_device> dev;

    public hlist_node index_hlist;

    public Ptr<bpf_prog> xdp_prog;

    public callback_head rcu;

    public @Unsigned int idx;

    public bpf_devmap_val val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dtab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dtab extends Struct {
    public bpf_map map;

    public Ptr<Ptr<bpf_dtab_netdev>> netdev_map;

    public list_head list;

    public Ptr<hlist_head> dev_index_head;

    public @OriginalName("spinlock_t") spinlock index_lock;

    public @Unsigned int items;

    public @Unsigned int n_buckets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cpumap_val"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cpumap_val extends Struct {
    public @Unsigned int qsize;

    public bpf_prog_of_bpf_cpumap_val_and_bpf_prog_of_bpf_devmap_val bpf_prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cpu_map_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cpu_map_entry extends Struct {
    public @Unsigned int cpu;

    public int map_id;

    public Ptr<xdp_bulk_queue> bulkq;

    public Ptr<ptr_ring> queue;

    public Ptr<task_struct> kthread;

    public bpf_cpumap_val value;

    public Ptr<bpf_prog> prog;

    public gro_node gro;

    public completion kthread_running;

    public rcu_work free_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cpu_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cpu_map extends Struct {
    public bpf_map map;

    public Ptr<Ptr<bpf_cpu_map_entry>> cpu_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_offload_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_offload_ops extends Struct {
    public Ptr<?> insn_hook;

    public Ptr<?> finalize;

    public Ptr<?> replace_insn;

    public Ptr<?> remove_insns;

    public Ptr<?> prepare;

    public Ptr<?> translate;

    public Ptr<?> destroy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_offload_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_offload_dev extends Struct {
    public Ptr<bpf_prog_offload_ops> ops;

    public list_head netdevs;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_offload_netdev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_offload_netdev extends Struct {
    public rhash_head l;

    public Ptr<net_device> netdev;

    public Ptr<bpf_offload_dev> offdev;

    public list_head progs;

    public list_head maps;

    public list_head offdev_netdevs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_netns_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_netns_link extends Struct {
    public bpf_link link;

    public Ptr<net> net;

    public list_head node;

    public netns_bpf_attach_type netns_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_stack_build_id_status"
  )
  public enum bpf_stack_build_id_status implements Enum<bpf_stack_build_id_status>, TypedEnum<bpf_stack_build_id_status, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_STACK_BUILD_ID_EMPTY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_STACK_BUILD_ID_EMPTY"
    )
    BPF_STACK_BUILD_ID_EMPTY,

    /**
     * {@code BPF_STACK_BUILD_ID_VALID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_STACK_BUILD_ID_VALID"
    )
    BPF_STACK_BUILD_ID_VALID,

    /**
     * {@code BPF_STACK_BUILD_ID_IP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_STACK_BUILD_ID_IP"
    )
    BPF_STACK_BUILD_ID_IP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stack_build_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stack_build_id extends Struct {
    public int status;

    public char @Size(20) [] build_id;

    @InlineUnion(17953)
    public @Unsigned long offset;

    @InlineUnion(17953)
    public @Unsigned long ip;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stack_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stack_map extends Struct {
    public bpf_map map;

    public Ptr<?> elems;

    public pcpu_freelist freelist;

    public @Unsigned int n_buckets;

    public Ptr<stack_map_bucket> @Size(0) [] buckets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__cgroup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__cgroup extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17979)
    public Ptr<cgroup> cgroup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_css"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_css extends Struct {
    public @Unsigned long @Size(3) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_css_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_css_kern extends Struct {
    public Ptr<cgroup_subsys_state> start;

    public Ptr<cgroup_subsys_state> pos;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cg_run_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cg_run_ctx extends Struct {
    public bpf_run_ctx run_ctx;

    public Ptr<bpf_prog_array_item> prog_item;

    public int retval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_skb_data_end"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_skb_data_end extends Struct {
    public qdisc_skb_cb qdisc_cb;

    public Ptr<?> data_meta;

    public Ptr<?> data_end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sockopt_buf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sockopt_buf extends Struct {
    public char @Size(32) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cgroup_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cgroup_link extends Struct {
    public bpf_link link;

    public Ptr<cgroup> cgroup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_prog_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_prog_list extends Struct {
    public hlist_node node;

    public Ptr<bpf_prog> prog;

    public Ptr<bpf_cgroup_link> link;

    public Ptr<bpf_cgroup_storage> @Size(2) [] storage;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_value"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_value extends Struct {
    public bpf_struct_ops_common_value common;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_map extends Struct {
    public bpf_map map;

    public Ptr<bpf_struct_ops_desc> st_ops_desc;

    public mutex lock;

    public Ptr<Ptr<bpf_link>> links;

    public Ptr<Ptr<bpf_ksym>> ksyms;

    public @Unsigned int funcs_cnt;

    public @Unsigned int image_pages_cnt;

    public Ptr<?> @Size(8) [] image_pages;

    public Ptr<btf> btf;

    public Ptr<bpf_struct_ops_value> uvalue;

    public bpf_struct_ops_value kvalue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_link extends Struct {
    public bpf_link link;

    public Ptr<bpf_map> map;

    public @OriginalName("wait_queue_head_t") wait_queue_head wait_hup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_cpumask"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_cpumask extends Struct {
    public @OriginalName("cpumask_t") cpumask cpumask;

    public @OriginalName("refcount_t") refcount_struct usage;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_crypto_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_crypto_type extends Struct {
    public Ptr<?> alloc_tfm;

    public Ptr<?> free_tfm;

    public Ptr<?> has_algo;

    public Ptr<?> setkey;

    public Ptr<?> setauthsize;

    public Ptr<?> encrypt;

    public Ptr<?> decrypt;

    public Ptr<?> ivsize;

    public Ptr<?> statesize;

    public Ptr<?> get_flags;

    public Ptr<module> owner;

    public char @Size(14) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_crypto_type_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_crypto_type_list extends Struct {
    public Ptr<bpf_crypto_type> type;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_crypto_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_crypto_params extends Struct {
    public char @Size(14) [] type;

    public char @Size(2) [] reserved;

    public char @Size(128) [] algo;

    public char @Size(256) [] key;

    public @Unsigned int key_len;

    public @Unsigned int authsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_crypto_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_crypto_ctx extends Struct {
    public Ptr<bpf_crypto_type> type;

    public Ptr<?> tfm;

    public @Unsigned int siv_len;

    public callback_head rcu;

    public @OriginalName("refcount_t") refcount_struct usage;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_kmem_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_kmem_cache extends Struct {
    public @Unsigned long @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_kmem_cache_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_kmem_cache_kern extends Struct {
    public Ptr<kmem_cache> pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__kmem_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__kmem_cache extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(18145)
    public Ptr<kmem_cache> s;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__dmabuf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__dmabuf extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(18210)
    public Ptr<dma_buf> dmabuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_dmabuf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_dmabuf extends Struct {
    public @Unsigned long @Size(1) [] __opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_dmabuf_kern"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_dmabuf_kern extends Struct {
    public Ptr<dma_buf> dmabuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_security_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_security_struct extends Struct {
    public @Unsigned int sid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_hid_bpf_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_hid_bpf_ops extends Struct {
    public bpf_struct_ops_common_value common;

    public hid_bpf_ops data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_ret_code"
  )
  public enum bpf_ret_code implements Enum<bpf_ret_code>, TypedEnum<bpf_ret_code, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_OK"
    )
    BPF_OK,

    /**
     * {@code BPF_DROP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_DROP"
    )
    BPF_DROP,

    /**
     * {@code BPF_REDIRECT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "BPF_REDIRECT"
    )
    BPF_REDIRECT,

    /**
     * {@code BPF_LWT_REROUTE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "BPF_LWT_REROUTE"
    )
    BPF_LWT_REROUTE,

    /**
     * {@code BPF_FLOW_DISSECTOR_CONTINUE = 129}
     */
    @EnumMember(
        value = 129L,
        name = "BPF_FLOW_DISSECTOR_CONTINUE"
    )
    BPF_FLOW_DISSECTOR_CONTINUE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_xdp_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_xdp_link extends Struct {
    public bpf_link link;

    public Ptr<net_device> dev;

    public int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_adj_room_mode"
  )
  public enum bpf_adj_room_mode implements Enum<bpf_adj_room_mode>, TypedEnum<bpf_adj_room_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_ADJ_ROOM_NET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_ADJ_ROOM_NET"
    )
    BPF_ADJ_ROOM_NET,

    /**
     * {@code BPF_ADJ_ROOM_MAC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_ADJ_ROOM_MAC"
    )
    BPF_ADJ_ROOM_MAC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_hdr_start_off"
  )
  public enum bpf_hdr_start_off implements Enum<bpf_hdr_start_off>, TypedEnum<bpf_hdr_start_off, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_HDR_START_MAC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_HDR_START_MAC"
    )
    BPF_HDR_START_MAC,

    /**
     * {@code BPF_HDR_START_NET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_HDR_START_NET"
    )
    BPF_HDR_START_NET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_lwt_encap_mode"
  )
  public enum bpf_lwt_encap_mode implements Enum<bpf_lwt_encap_mode>, TypedEnum<bpf_lwt_encap_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_LWT_ENCAP_SEG6 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_LWT_ENCAP_SEG6"
    )
    BPF_LWT_ENCAP_SEG6,

    /**
     * {@code BPF_LWT_ENCAP_SEG6_INLINE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_LWT_ENCAP_SEG6_INLINE"
    )
    BPF_LWT_ENCAP_SEG6_INLINE,

    /**
     * {@code BPF_LWT_ENCAP_IP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_LWT_ENCAP_IP"
    )
    BPF_LWT_ENCAP_IP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tunnel_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tunnel_key extends Struct {
    public @Unsigned int tunnel_id;

    @InlineUnion(58703)
    public @Unsigned int remote_ipv4;

    @InlineUnion(58703)
    public @Unsigned int @Size(4) [] remote_ipv6;

    public char tunnel_tos;

    public char tunnel_ttl;

    @InlineUnion(58704)
    public @Unsigned short tunnel_ext;

    @InlineUnion(58704)
    public @Unsigned @OriginalName("__be16") short tunnel_flags;

    public @Unsigned int tunnel_label;

    @InlineUnion(58705)
    public @Unsigned int local_ipv4;

    @InlineUnion(58705)
    public @Unsigned int @Size(4) [] local_ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_xfrm_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_xfrm_state extends Struct {
    public @Unsigned int reqid;

    public @Unsigned int spi;

    public @Unsigned short family;

    public @Unsigned short ext;

    @InlineUnion(58703)
    public @Unsigned int remote_ipv4;

    @InlineUnion(58703)
    public @Unsigned int @Size(4) [] remote_ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tcp_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tcp_sock extends Struct {
    public @Unsigned int snd_cwnd;

    public @Unsigned int srtt_us;

    public @Unsigned int rtt_min;

    public @Unsigned int snd_ssthresh;

    public @Unsigned int rcv_nxt;

    public @Unsigned int snd_nxt;

    public @Unsigned int snd_una;

    public @Unsigned int mss_cache;

    public @Unsigned int ecn_flags;

    public @Unsigned int rate_delivered;

    public @Unsigned int rate_interval_us;

    public @Unsigned int packets_out;

    public @Unsigned int retrans_out;

    public @Unsigned int total_retrans;

    public @Unsigned int segs_in;

    public @Unsigned int data_segs_in;

    public @Unsigned int segs_out;

    public @Unsigned int data_segs_out;

    public @Unsigned int lost_out;

    public @Unsigned int sacked_out;

    public @Unsigned long bytes_received;

    public @Unsigned long bytes_acked;

    public @Unsigned int dsack_dups;

    public @Unsigned int delivered;

    public @Unsigned int delivered_ce;

    public @Unsigned int icsk_retransmits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sock_tuple"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sock_tuple extends Struct {
    @InlineUnion(58712)
    public ipv4_of_anon_member_of_bpf_sock_tuple ipv4;

    @InlineUnion(58712)
    public ipv6_of_anon_member_of_bpf_sock_tuple ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_xdp_sock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_xdp_sock extends Struct {
    public @Unsigned int queue_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_fib_lookup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_fib_lookup extends Struct {
    public char family;

    public char l4_protocol;

    public @Unsigned @OriginalName("__be16") short sport;

    public @Unsigned @OriginalName("__be16") short dport;

    @InlineUnion(58721)
    public @Unsigned short tot_len;

    @InlineUnion(58721)
    public @Unsigned short mtu_result;

    public @Unsigned int ifindex;

    @InlineUnion(58722)
    public char tos;

    @InlineUnion(58722)
    public @Unsigned @OriginalName("__be32") int flowinfo;

    @InlineUnion(58722)
    public @Unsigned int rt_metric;

    @InlineUnion(58723)
    public @Unsigned @OriginalName("__be32") int ipv4_src;

    @InlineUnion(58723)
    public @Unsigned int @Size(4) [] ipv6_src;

    @InlineUnion(58724)
    public @Unsigned @OriginalName("__be32") int ipv4_dst;

    @InlineUnion(58724)
    public @Unsigned int @Size(4) [] ipv6_dst;

    @InlineUnion(58726)
    public anon_member_of_anon_member_of_bpf_fib_lookup anon9$0;

    @InlineUnion(58726)
    public @Unsigned int tbid;

    @InlineUnion(58729)
    public anon_member_of_anon_member_of_bpf_fib_lookup anon10$0;

    @InlineUnion(58729)
    public anon_member_of_anon_member_of_bpf_fib_lookup anon10$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_redir_neigh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_redir_neigh extends Struct {
    public @Unsigned int nh_family;

    @InlineUnion(58731)
    public @Unsigned @OriginalName("__be32") int ipv4_nh;

    @InlineUnion(58731)
    public @Unsigned int @Size(4) [] ipv6_nh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_check_mtu_flags"
  )
  public enum bpf_check_mtu_flags implements Enum<bpf_check_mtu_flags>, TypedEnum<bpf_check_mtu_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MTU_CHK_SEGS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_MTU_CHK_SEGS"
    )
    BPF_MTU_CHK_SEGS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum bpf_check_mtu_ret"
  )
  public enum bpf_check_mtu_ret implements Enum<bpf_check_mtu_ret>, TypedEnum<bpf_check_mtu_ret, java.lang. @Unsigned Integer> {
    /**
     * {@code BPF_MTU_CHK_RET_SUCCESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BPF_MTU_CHK_RET_SUCCESS"
    )
    BPF_MTU_CHK_RET_SUCCESS,

    /**
     * {@code BPF_MTU_CHK_RET_FRAG_NEEDED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BPF_MTU_CHK_RET_FRAG_NEEDED"
    )
    BPF_MTU_CHK_RET_FRAG_NEEDED,

    /**
     * {@code BPF_MTU_CHK_RET_SEGS_TOOBIG = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BPF_MTU_CHK_RET_SEGS_TOOBIG"
    )
    BPF_MTU_CHK_RET_SEGS_TOOBIG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tcp_req_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tcp_req_attrs extends Struct {
    public @Unsigned int rcv_tsval;

    public @Unsigned int rcv_tsecr;

    public @Unsigned short mss;

    public char rcv_wscale;

    public char snd_wscale;

    public char ecn_ok;

    public char wscale_ok;

    public char sack_ok;

    public char tstamp_ok;

    public char usec_ts_ok;

    public char @Size(3) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lwt_prog"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lwt_prog extends Struct {
    public Ptr<bpf_prog> prog;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_lwt"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_lwt extends Struct {
    public bpf_lwt_prog in;

    public bpf_lwt_prog out;

    public bpf_lwt_prog xmit;

    public int family;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_stab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_stab extends Struct {
    public bpf_map map;

    public Ptr<Ptr<sock>> sks;

    public sk_psock_progs progs;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__sockmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__sockmap extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17232)
    public Ptr<bpf_map> map;

    @InlineUnion(17283)
    public Ptr<?> key;

    @InlineUnion(60337)
    public Ptr<sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_shtab_elem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_shtab_elem extends Struct {
    public callback_head rcu;

    public @Unsigned int hash;

    public Ptr<sock> sk;

    public hlist_node node;

    public char @Size(0) [] key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_shtab_bucket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_shtab_bucket extends Struct {
    public hlist_head head;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_shtab"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_shtab extends Struct {
    public bpf_map map;

    public Ptr<bpf_shtab_bucket> buckets;

    public @Unsigned int buckets_num;

    public @Unsigned int elem_size;

    public sk_psock_progs progs;

    public atomic_t count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sk_storage_diag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sk_storage_diag extends Struct {
    public @Unsigned int nr_maps;

    public Ptr<bpf_map> @Size(0) [] maps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter_seq_sk_storage_map_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter_seq_sk_storage_map_info extends Struct {
    public Ptr<bpf_map> map;

    public @Unsigned int bucket_id;

    public @Unsigned int skip_elems;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__bpf_sk_storage_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__bpf_sk_storage_map extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(17232)
    public Ptr<bpf_map> map;

    @InlineUnion(60337)
    public Ptr<sock> sk;

    @InlineUnion(17284)
    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sched_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sched_data extends Struct {
    public qdisc_watchdog watchdog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_sk_buff_ptr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_sk_buff_ptr extends Struct {
    public Ptr<sk_buff> skb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_Qdisc_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_Qdisc_ops extends Struct {
    public bpf_struct_ops_common_value common;

    public Qdisc_ops data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__netlink"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__netlink extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(60795)
    public Ptr<netlink_sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_test_timer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_test_timer extends Struct {
    public mode_of_bpf_test_timer mode;

    public @Unsigned int i;

    public @Unsigned long time_start;

    public @Unsigned long time_spent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_fentry_test_t"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_fentry_test_t extends Struct {
    public Ptr<bpf_fentry_test_t> a;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_raw_tp_test_run_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_raw_tp_test_run_info extends Struct {
    public Ptr<bpf_prog> prog;

    public Ptr<?> ctx;

    public @Unsigned int retval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dummy_ops_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dummy_ops_state extends Struct {
    public int val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dummy_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dummy_ops extends Struct {
    public Ptr<?> test_1;

    public Ptr<?> test_2;

    public Ptr<?> test_sleepable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_dummy_ops_test_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_dummy_ops_test_args extends Struct {
    public @Unsigned long @Size(12) [] args;

    public bpf_dummy_ops_state state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_bpf_dummy_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_bpf_dummy_ops extends Struct {
    public bpf_struct_ops_common_value common;

    public bpf_dummy_ops data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_nf_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_nf_link extends Struct {
    public bpf_link link;

    public nf_hook_ops hook_ops;

    public @OriginalName("netns_tracker") lockdep_map_p ns_tracker;

    public Ptr<net> net;

    public @Unsigned int dead;

    public Ptr<nf_defrag_hook> defrag_hook;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union bpf_tcp_iter_batch_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tcp_iter_batch_item extends Union {
    public Ptr<sock> sk;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_tcp_iter_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_tcp_iter_state extends Struct {
    public tcp_iter_state state;

    public @Unsigned int cur_sk;

    public @Unsigned int end_sk;

    public @Unsigned int max_sk;

    public Ptr<bpf_tcp_iter_batch_item> batch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__tcp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__tcp extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(61918)
    public Ptr<sock_common> sk_common;

    public @Unsigned @OriginalName("uid_t") int uid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__udp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__udp extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(62019)
    public Ptr<udp_sock> udp_sk;

    public @Unsigned @OriginalName("uid_t") int uid;

    public int bucket;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union bpf_udp_iter_batch_item"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_udp_iter_batch_item extends Union {
    public Ptr<sock> sk;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_udp_iter_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_udp_iter_state extends Struct {
    public udp_iter_state state;

    public @Unsigned int cur_sk;

    public @Unsigned int end_sk;

    public @Unsigned int max_sk;

    public Ptr<bpf_udp_iter_batch_item> batch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_struct_ops_tcp_congestion_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_struct_ops_tcp_congestion_ops extends Struct {
    public bpf_struct_ops_common_value common;

    public tcp_congestion_ops data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_xfrm_state_opts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_xfrm_state_opts extends Struct {
    public int error;

    public int netns_id;

    public @Unsigned int mark;

    public xfrm_address_t daddr;

    public @Unsigned @OriginalName("__be32") int spi;

    public char proto;

    public @Unsigned short family;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_unix_iter_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_unix_iter_state extends Struct {
    public seq_net_private p;

    public @Unsigned int cur_sk;

    public @Unsigned int end_sk;

    public @Unsigned int max_sk;

    public Ptr<Ptr<sock>> batch;

    public boolean st_bucket_done;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__unix"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__unix extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(62948)
    public Ptr<unix_sock> unix_sk;

    public @Unsigned @OriginalName("uid_t") int uid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct bpf_iter__ipv6_route"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class bpf_iter__ipv6_route extends Struct {
    @InlineUnion(14009)
    public Ptr<bpf_iter_meta> meta;

    @InlineUnion(63167)
    public Ptr<fib6_info> rt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const struct btf*; unsigned int id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType394349340C48 extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int id;
  }
}
