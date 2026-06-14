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
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
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
 * Generated class for BPF runtime types that start with flow
 */
@java.lang.SuppressWarnings("unused")
public final class FlowDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__flow_hash_from_keys($arg1, (const struct {\n"
          + "  long long unsigned int key[2];\n"
          + "}*)$arg2)")
  public static @Unsigned int __flow_hash_from_keys(Ptr<flow_keys> keys,
      Ptr<siphash_key_t> keyval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<flow_action_cookie> flow_action_cookie_create(Ptr<?> data, @Unsigned int len,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void flow_action_cookie_destroy(Ptr<flow_action_cookie> cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_block_cb_alloc($arg1, $arg2, $arg3, (void (*)(void*))$arg4)")
  public static Ptr<flow_block_cb> flow_block_cb_alloc(Ptr<?> cb, Ptr<?> cb_ident, Ptr<?> cb_priv,
      Ptr<?> release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int flow_block_cb_decref(Ptr<flow_block_cb> block_cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void flow_block_cb_free(Ptr<flow_block_cb> block_cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void flow_block_cb_incref(Ptr<flow_block_cb> block_cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean flow_block_cb_is_busy(Ptr<?> cb, Ptr<?> cb_ident,
      Ptr<list_head> driver_block_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<flow_block_cb> flow_block_cb_lookup(Ptr<flow_block> block, Ptr<?> cb,
      Ptr<?> cb_ident) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> flow_block_cb_priv(Ptr<flow_block_cb> block_cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int flow_block_cb_setup_simple(Ptr<flow_block_offload> f,
      Ptr<list_head> driver_block_list, Ptr<?> cb, Ptr<?> cb_ident, Ptr<?> cb_priv,
      boolean ingress_only) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int flow_dissector_bpf_prog_attach_check(Ptr<net> net, Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_dissector_convert_ctx_access($arg1, (const struct bpf_insn*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int flow_dissector_convert_ctx_access(bpf_access_type type,
      Ptr<bpf_insn> si, Ptr<bpf_insn> insn_buf, Ptr<bpf_prog> prog,
      Ptr<java.lang. @Unsigned Integer> target_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct bpf_func_proto*)flow_dissector_func_proto($arg1, (const struct bpf_prog*)$arg2))")
  public static Ptr<bpf_func_proto> flow_dissector_func_proto(bpf_func_id func_id,
      Ptr<bpf_prog> prog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_dissector_is_valid_access($arg1, $arg2, $arg3, (const struct bpf_prog*)$arg4, $arg5)")
  public static boolean flow_dissector_is_valid_access(int off, int size, bpf_access_type type,
      Ptr<bpf_prog> prog, Ptr<bpf_insn_access_aux> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_get_u32_dst((const struct flow_keys*)$arg1)")
  public static @Unsigned @OriginalName("__be32") int flow_get_u32_dst(Ptr<flow_keys> flow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_get_u32_src((const struct flow_keys*)$arg1)")
  public static @Unsigned @OriginalName("__be32") int flow_get_u32_src(Ptr<flow_keys> flow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int flow_hash_from_keys(Ptr<flow_keys> keys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_hash_from_keys_seed($arg1, (const struct {\n"
          + "  long long unsigned int key[2];\n"
          + "}*)$arg2)")
  public static @Unsigned int flow_hash_from_keys_seed(Ptr<flow_keys> keys,
      Ptr<siphash_key_t> keyval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_indr_block_cb_alloc($arg1, $arg2, $arg3, (void (*)(void*))$arg4, $arg5, $arg6, $arg7, $arg8, $arg9, (void (*)(struct flow_block_cb*))$arg10)")
  public static Ptr<flow_block_cb> flow_indr_block_cb_alloc(Ptr<?> cb, Ptr<?> cb_ident,
      Ptr<?> cb_priv, Ptr<?> release, Ptr<flow_block_offload> bo, Ptr<net_device> dev,
      Ptr<Qdisc> sch, Ptr<?> data, Ptr<?> indr_cb_priv, Ptr<?> cleanup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean flow_indr_dev_exists() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int flow_indr_dev_register(Ptr<?> cb, Ptr<?> cb_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_indr_dev_setup_offload($arg1, $arg2, $arg3, $arg4, $arg5, (void (*)(struct flow_block_cb*))$arg6)")
  public static int flow_indr_dev_setup_offload(Ptr<net_device> dev, Ptr<Qdisc> sch,
      tc_setup_type type, Ptr<?> data, Ptr<flow_block_offload> bo, Ptr<?> cleanup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_indr_dev_unregister($arg1, $arg2, (void (*)(void*))$arg3)")
  public static void flow_indr_dev_unregister(Ptr<?> cb, Ptr<?> cb_priv, Ptr<?> release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_limit_cpu_sysctl((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int flow_limit_cpu_sysctl(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_limit_table_len_sysctl((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int flow_limit_table_len_sysctl(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<flow_rule> flow_rule_alloc(@Unsigned int num_actions) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_arp((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_arp(Ptr<flow_rule> rule, Ptr<flow_match_arp> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_basic((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_basic(Ptr<flow_rule> rule, Ptr<flow_match_basic> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_control((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_control(Ptr<flow_rule> rule, Ptr<flow_match_control> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ct((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ct(Ptr<flow_rule> rule, Ptr<flow_match_ct> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_cvlan((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_cvlan(Ptr<flow_rule> rule, Ptr<flow_match_vlan> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_control((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_control(Ptr<flow_rule> rule, Ptr<flow_match_control> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_ip((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_ip(Ptr<flow_rule> rule, Ptr<flow_match_ip> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_ipv4_addrs((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_ipv4_addrs(Ptr<flow_rule> rule,
      Ptr<flow_match_ipv4_addrs> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_ipv6_addrs((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_ipv6_addrs(Ptr<flow_rule> rule,
      Ptr<flow_match_ipv6_addrs> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_keyid((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_keyid(Ptr<flow_rule> rule, Ptr<flow_match_enc_keyid> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_opts((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_opts(Ptr<flow_rule> rule, Ptr<flow_match_enc_opts> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_enc_ports((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_enc_ports(Ptr<flow_rule> rule, Ptr<flow_match_ports> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_eth_addrs((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_eth_addrs(Ptr<flow_rule> rule, Ptr<flow_match_eth_addrs> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_icmp((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_icmp(Ptr<flow_rule> rule, Ptr<flow_match_icmp> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ip((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ip(Ptr<flow_rule> rule, Ptr<flow_match_ip> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ipsec((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ipsec(Ptr<flow_rule> rule, Ptr<flow_match_ipsec> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ipv4_addrs((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ipv4_addrs(Ptr<flow_rule> rule,
      Ptr<flow_match_ipv4_addrs> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ipv6_addrs((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ipv6_addrs(Ptr<flow_rule> rule,
      Ptr<flow_match_ipv6_addrs> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_l2tpv3((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_l2tpv3(Ptr<flow_rule> rule, Ptr<flow_match_l2tpv3> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_meta((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_meta(Ptr<flow_rule> rule, Ptr<flow_match_meta> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_mpls((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_mpls(Ptr<flow_rule> rule, Ptr<flow_match_mpls> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ports((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ports(Ptr<flow_rule> rule, Ptr<flow_match_ports> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_ports_range((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_ports_range(Ptr<flow_rule> rule,
      Ptr<flow_match_ports_range> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_pppoe((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_pppoe(Ptr<flow_rule> rule, Ptr<flow_match_pppoe> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_tcp((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_tcp(Ptr<flow_rule> rule, Ptr<flow_match_tcp> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("flow_rule_match_vlan((const struct flow_rule*)$arg1, $arg2)")
  public static void flow_rule_match_vlan(Ptr<flow_rule> rule, Ptr<flow_match_vlan> out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_dissector_key_id"
  )
  public enum flow_dissector_key_id implements Enum<flow_dissector_key_id>, TypedEnum<flow_dissector_key_id, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_DISSECTOR_KEY_CONTROL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_DISSECTOR_KEY_CONTROL"
    )
    FLOW_DISSECTOR_KEY_CONTROL,

    /**
     * {@code FLOW_DISSECTOR_KEY_BASIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_DISSECTOR_KEY_BASIC"
    )
    FLOW_DISSECTOR_KEY_BASIC,

    /**
     * {@code FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_DISSECTOR_KEY_IPV4_ADDRS"
    )
    FLOW_DISSECTOR_KEY_IPV4_ADDRS,

    /**
     * {@code FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_DISSECTOR_KEY_IPV6_ADDRS"
    )
    FLOW_DISSECTOR_KEY_IPV6_ADDRS,

    /**
     * {@code FLOW_DISSECTOR_KEY_PORTS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_DISSECTOR_KEY_PORTS"
    )
    FLOW_DISSECTOR_KEY_PORTS,

    /**
     * {@code FLOW_DISSECTOR_KEY_PORTS_RANGE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FLOW_DISSECTOR_KEY_PORTS_RANGE"
    )
    FLOW_DISSECTOR_KEY_PORTS_RANGE,

    /**
     * {@code FLOW_DISSECTOR_KEY_ICMP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FLOW_DISSECTOR_KEY_ICMP"
    )
    FLOW_DISSECTOR_KEY_ICMP,

    /**
     * {@code FLOW_DISSECTOR_KEY_ETH_ADDRS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "FLOW_DISSECTOR_KEY_ETH_ADDRS"
    )
    FLOW_DISSECTOR_KEY_ETH_ADDRS,

    /**
     * {@code FLOW_DISSECTOR_KEY_TIPC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FLOW_DISSECTOR_KEY_TIPC"
    )
    FLOW_DISSECTOR_KEY_TIPC,

    /**
     * {@code FLOW_DISSECTOR_KEY_ARP = 9}
     */
    @EnumMember(
        value = 9L,
        name = "FLOW_DISSECTOR_KEY_ARP"
    )
    FLOW_DISSECTOR_KEY_ARP,

    /**
     * {@code FLOW_DISSECTOR_KEY_VLAN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "FLOW_DISSECTOR_KEY_VLAN"
    )
    FLOW_DISSECTOR_KEY_VLAN,

    /**
     * {@code FLOW_DISSECTOR_KEY_FLOW_LABEL = 11}
     */
    @EnumMember(
        value = 11L,
        name = "FLOW_DISSECTOR_KEY_FLOW_LABEL"
    )
    FLOW_DISSECTOR_KEY_FLOW_LABEL,

    /**
     * {@code FLOW_DISSECTOR_KEY_GRE_KEYID = 12}
     */
    @EnumMember(
        value = 12L,
        name = "FLOW_DISSECTOR_KEY_GRE_KEYID"
    )
    FLOW_DISSECTOR_KEY_GRE_KEYID,

    /**
     * {@code FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13}
     */
    @EnumMember(
        value = 13L,
        name = "FLOW_DISSECTOR_KEY_MPLS_ENTROPY"
    )
    FLOW_DISSECTOR_KEY_MPLS_ENTROPY,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_KEYID = 14}
     */
    @EnumMember(
        value = 14L,
        name = "FLOW_DISSECTOR_KEY_ENC_KEYID"
    )
    FLOW_DISSECTOR_KEY_ENC_KEYID,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15}
     */
    @EnumMember(
        value = 15L,
        name = "FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS"
    )
    FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16}
     */
    @EnumMember(
        value = 16L,
        name = "FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS"
    )
    FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_CONTROL = 17}
     */
    @EnumMember(
        value = 17L,
        name = "FLOW_DISSECTOR_KEY_ENC_CONTROL"
    )
    FLOW_DISSECTOR_KEY_ENC_CONTROL,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_PORTS = 18}
     */
    @EnumMember(
        value = 18L,
        name = "FLOW_DISSECTOR_KEY_ENC_PORTS"
    )
    FLOW_DISSECTOR_KEY_ENC_PORTS,

    /**
     * {@code FLOW_DISSECTOR_KEY_MPLS = 19}
     */
    @EnumMember(
        value = 19L,
        name = "FLOW_DISSECTOR_KEY_MPLS"
    )
    FLOW_DISSECTOR_KEY_MPLS,

    /**
     * {@code FLOW_DISSECTOR_KEY_TCP = 20}
     */
    @EnumMember(
        value = 20L,
        name = "FLOW_DISSECTOR_KEY_TCP"
    )
    FLOW_DISSECTOR_KEY_TCP,

    /**
     * {@code FLOW_DISSECTOR_KEY_IP = 21}
     */
    @EnumMember(
        value = 21L,
        name = "FLOW_DISSECTOR_KEY_IP"
    )
    FLOW_DISSECTOR_KEY_IP,

    /**
     * {@code FLOW_DISSECTOR_KEY_CVLAN = 22}
     */
    @EnumMember(
        value = 22L,
        name = "FLOW_DISSECTOR_KEY_CVLAN"
    )
    FLOW_DISSECTOR_KEY_CVLAN,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_IP = 23}
     */
    @EnumMember(
        value = 23L,
        name = "FLOW_DISSECTOR_KEY_ENC_IP"
    )
    FLOW_DISSECTOR_KEY_ENC_IP,

    /**
     * {@code FLOW_DISSECTOR_KEY_ENC_OPTS = 24}
     */
    @EnumMember(
        value = 24L,
        name = "FLOW_DISSECTOR_KEY_ENC_OPTS"
    )
    FLOW_DISSECTOR_KEY_ENC_OPTS,

    /**
     * {@code FLOW_DISSECTOR_KEY_META = 25}
     */
    @EnumMember(
        value = 25L,
        name = "FLOW_DISSECTOR_KEY_META"
    )
    FLOW_DISSECTOR_KEY_META,

    /**
     * {@code FLOW_DISSECTOR_KEY_CT = 26}
     */
    @EnumMember(
        value = 26L,
        name = "FLOW_DISSECTOR_KEY_CT"
    )
    FLOW_DISSECTOR_KEY_CT,

    /**
     * {@code FLOW_DISSECTOR_KEY_HASH = 27}
     */
    @EnumMember(
        value = 27L,
        name = "FLOW_DISSECTOR_KEY_HASH"
    )
    FLOW_DISSECTOR_KEY_HASH,

    /**
     * {@code FLOW_DISSECTOR_KEY_NUM_OF_VLANS = 28}
     */
    @EnumMember(
        value = 28L,
        name = "FLOW_DISSECTOR_KEY_NUM_OF_VLANS"
    )
    FLOW_DISSECTOR_KEY_NUM_OF_VLANS,

    /**
     * {@code FLOW_DISSECTOR_KEY_PPPOE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "FLOW_DISSECTOR_KEY_PPPOE"
    )
    FLOW_DISSECTOR_KEY_PPPOE,

    /**
     * {@code FLOW_DISSECTOR_KEY_L2TPV3 = 30}
     */
    @EnumMember(
        value = 30L,
        name = "FLOW_DISSECTOR_KEY_L2TPV3"
    )
    FLOW_DISSECTOR_KEY_L2TPV3,

    /**
     * {@code FLOW_DISSECTOR_KEY_CFM = 31}
     */
    @EnumMember(
        value = 31L,
        name = "FLOW_DISSECTOR_KEY_CFM"
    )
    FLOW_DISSECTOR_KEY_CFM,

    /**
     * {@code FLOW_DISSECTOR_KEY_IPSEC = 32}
     */
    @EnumMember(
        value = 32L,
        name = "FLOW_DISSECTOR_KEY_IPSEC"
    )
    FLOW_DISSECTOR_KEY_IPSEC,

    /**
     * {@code FLOW_DISSECTOR_KEY_MAX = 33}
     */
    @EnumMember(
        value = 33L,
        name = "FLOW_DISSECTOR_KEY_MAX"
    )
    FLOW_DISSECTOR_KEY_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock lock; _Bool stopped; _Bool tco_stopped; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_of_tty_struct extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public boolean stopped;

    public boolean tco_stopped;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_action_hw_stats_bit"
  )
  public enum flow_action_hw_stats_bit implements Enum<flow_action_hw_stats_bit>, TypedEnum<flow_action_hw_stats_bit, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_ACTION_HW_STATS_IMMEDIATE_BIT"
    )
    FLOW_ACTION_HW_STATS_IMMEDIATE_BIT,

    /**
     * {@code FLOW_ACTION_HW_STATS_DELAYED_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_ACTION_HW_STATS_DELAYED_BIT"
    )
    FLOW_ACTION_HW_STATS_DELAYED_BIT,

    /**
     * {@code FLOW_ACTION_HW_STATS_DISABLED_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_ACTION_HW_STATS_DISABLED_BIT"
    )
    FLOW_ACTION_HW_STATS_DISABLED_BIT,

    /**
     * {@code FLOW_ACTION_HW_STATS_NUM_BITS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_ACTION_HW_STATS_NUM_BITS"
    )
    FLOW_ACTION_HW_STATS_NUM_BITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_block extends Struct {
    public list_head cb_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_control"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_control extends Struct {
    public @Unsigned short thoff;

    public @Unsigned short addr_type;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_basic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_basic extends Struct {
    public @Unsigned @OriginalName("__be16") short n_proto;

    public char ip_proto;

    public char padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector extends Struct {
    public @Unsigned long used_keys;

    public @Unsigned short @Size(33) [] offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_keys_basic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_keys_basic extends Struct {
    public flow_dissector_key_control control;

    public flow_dissector_key_basic basic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match extends Struct {
    public Ptr<flow_dissector> dissector;

    public Ptr<?> mask;

    public Ptr<?> key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_action_id"
  )
  public enum flow_action_id implements Enum<flow_action_id>, TypedEnum<flow_action_id, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_ACTION_ACCEPT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_ACTION_ACCEPT"
    )
    FLOW_ACTION_ACCEPT,

    /**
     * {@code FLOW_ACTION_DROP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_ACTION_DROP"
    )
    FLOW_ACTION_DROP,

    /**
     * {@code FLOW_ACTION_TRAP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_ACTION_TRAP"
    )
    FLOW_ACTION_TRAP,

    /**
     * {@code FLOW_ACTION_GOTO = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_ACTION_GOTO"
    )
    FLOW_ACTION_GOTO,

    /**
     * {@code FLOW_ACTION_REDIRECT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_ACTION_REDIRECT"
    )
    FLOW_ACTION_REDIRECT,

    /**
     * {@code FLOW_ACTION_MIRRED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FLOW_ACTION_MIRRED"
    )
    FLOW_ACTION_MIRRED,

    /**
     * {@code FLOW_ACTION_REDIRECT_INGRESS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "FLOW_ACTION_REDIRECT_INGRESS"
    )
    FLOW_ACTION_REDIRECT_INGRESS,

    /**
     * {@code FLOW_ACTION_MIRRED_INGRESS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "FLOW_ACTION_MIRRED_INGRESS"
    )
    FLOW_ACTION_MIRRED_INGRESS,

    /**
     * {@code FLOW_ACTION_VLAN_PUSH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FLOW_ACTION_VLAN_PUSH"
    )
    FLOW_ACTION_VLAN_PUSH,

    /**
     * {@code FLOW_ACTION_VLAN_POP = 9}
     */
    @EnumMember(
        value = 9L,
        name = "FLOW_ACTION_VLAN_POP"
    )
    FLOW_ACTION_VLAN_POP,

    /**
     * {@code FLOW_ACTION_VLAN_MANGLE = 10}
     */
    @EnumMember(
        value = 10L,
        name = "FLOW_ACTION_VLAN_MANGLE"
    )
    FLOW_ACTION_VLAN_MANGLE,

    /**
     * {@code FLOW_ACTION_TUNNEL_ENCAP = 11}
     */
    @EnumMember(
        value = 11L,
        name = "FLOW_ACTION_TUNNEL_ENCAP"
    )
    FLOW_ACTION_TUNNEL_ENCAP,

    /**
     * {@code FLOW_ACTION_TUNNEL_DECAP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "FLOW_ACTION_TUNNEL_DECAP"
    )
    FLOW_ACTION_TUNNEL_DECAP,

    /**
     * {@code FLOW_ACTION_MANGLE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "FLOW_ACTION_MANGLE"
    )
    FLOW_ACTION_MANGLE,

    /**
     * {@code FLOW_ACTION_ADD = 14}
     */
    @EnumMember(
        value = 14L,
        name = "FLOW_ACTION_ADD"
    )
    FLOW_ACTION_ADD,

    /**
     * {@code FLOW_ACTION_CSUM = 15}
     */
    @EnumMember(
        value = 15L,
        name = "FLOW_ACTION_CSUM"
    )
    FLOW_ACTION_CSUM,

    /**
     * {@code FLOW_ACTION_MARK = 16}
     */
    @EnumMember(
        value = 16L,
        name = "FLOW_ACTION_MARK"
    )
    FLOW_ACTION_MARK,

    /**
     * {@code FLOW_ACTION_PTYPE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "FLOW_ACTION_PTYPE"
    )
    FLOW_ACTION_PTYPE,

    /**
     * {@code FLOW_ACTION_PRIORITY = 18}
     */
    @EnumMember(
        value = 18L,
        name = "FLOW_ACTION_PRIORITY"
    )
    FLOW_ACTION_PRIORITY,

    /**
     * {@code FLOW_ACTION_RX_QUEUE_MAPPING = 19}
     */
    @EnumMember(
        value = 19L,
        name = "FLOW_ACTION_RX_QUEUE_MAPPING"
    )
    FLOW_ACTION_RX_QUEUE_MAPPING,

    /**
     * {@code FLOW_ACTION_WAKE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "FLOW_ACTION_WAKE"
    )
    FLOW_ACTION_WAKE,

    /**
     * {@code FLOW_ACTION_QUEUE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "FLOW_ACTION_QUEUE"
    )
    FLOW_ACTION_QUEUE,

    /**
     * {@code FLOW_ACTION_SAMPLE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "FLOW_ACTION_SAMPLE"
    )
    FLOW_ACTION_SAMPLE,

    /**
     * {@code FLOW_ACTION_POLICE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "FLOW_ACTION_POLICE"
    )
    FLOW_ACTION_POLICE,

    /**
     * {@code FLOW_ACTION_CT = 24}
     */
    @EnumMember(
        value = 24L,
        name = "FLOW_ACTION_CT"
    )
    FLOW_ACTION_CT,

    /**
     * {@code FLOW_ACTION_CT_METADATA = 25}
     */
    @EnumMember(
        value = 25L,
        name = "FLOW_ACTION_CT_METADATA"
    )
    FLOW_ACTION_CT_METADATA,

    /**
     * {@code FLOW_ACTION_MPLS_PUSH = 26}
     */
    @EnumMember(
        value = 26L,
        name = "FLOW_ACTION_MPLS_PUSH"
    )
    FLOW_ACTION_MPLS_PUSH,

    /**
     * {@code FLOW_ACTION_MPLS_POP = 27}
     */
    @EnumMember(
        value = 27L,
        name = "FLOW_ACTION_MPLS_POP"
    )
    FLOW_ACTION_MPLS_POP,

    /**
     * {@code FLOW_ACTION_MPLS_MANGLE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "FLOW_ACTION_MPLS_MANGLE"
    )
    FLOW_ACTION_MPLS_MANGLE,

    /**
     * {@code FLOW_ACTION_GATE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "FLOW_ACTION_GATE"
    )
    FLOW_ACTION_GATE,

    /**
     * {@code FLOW_ACTION_PPPOE_PUSH = 30}
     */
    @EnumMember(
        value = 30L,
        name = "FLOW_ACTION_PPPOE_PUSH"
    )
    FLOW_ACTION_PPPOE_PUSH,

    /**
     * {@code FLOW_ACTION_JUMP = 31}
     */
    @EnumMember(
        value = 31L,
        name = "FLOW_ACTION_JUMP"
    )
    FLOW_ACTION_JUMP,

    /**
     * {@code FLOW_ACTION_PIPE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "FLOW_ACTION_PIPE"
    )
    FLOW_ACTION_PIPE,

    /**
     * {@code FLOW_ACTION_VLAN_PUSH_ETH = 33}
     */
    @EnumMember(
        value = 33L,
        name = "FLOW_ACTION_VLAN_PUSH_ETH"
    )
    FLOW_ACTION_VLAN_PUSH_ETH,

    /**
     * {@code FLOW_ACTION_VLAN_POP_ETH = 34}
     */
    @EnumMember(
        value = 34L,
        name = "FLOW_ACTION_VLAN_POP_ETH"
    )
    FLOW_ACTION_VLAN_POP_ETH,

    /**
     * {@code FLOW_ACTION_CONTINUE = 35}
     */
    @EnumMember(
        value = 35L,
        name = "FLOW_ACTION_CONTINUE"
    )
    FLOW_ACTION_CONTINUE,

    /**
     * {@code NUM_FLOW_ACTIONS = 36}
     */
    @EnumMember(
        value = 36L,
        name = "NUM_FLOW_ACTIONS"
    )
    NUM_FLOW_ACTIONS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_action_mangle_base"
  )
  public enum flow_action_mangle_base implements Enum<flow_action_mangle_base>, TypedEnum<flow_action_mangle_base, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_ACT_MANGLE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_ACT_MANGLE_UNSPEC"
    )
    FLOW_ACT_MANGLE_UNSPEC,

    /**
     * {@code FLOW_ACT_MANGLE_HDR_TYPE_ETH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_ACT_MANGLE_HDR_TYPE_ETH"
    )
    FLOW_ACT_MANGLE_HDR_TYPE_ETH,

    /**
     * {@code FLOW_ACT_MANGLE_HDR_TYPE_IP4 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_ACT_MANGLE_HDR_TYPE_IP4"
    )
    FLOW_ACT_MANGLE_HDR_TYPE_IP4,

    /**
     * {@code FLOW_ACT_MANGLE_HDR_TYPE_IP6 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_ACT_MANGLE_HDR_TYPE_IP6"
    )
    FLOW_ACT_MANGLE_HDR_TYPE_IP6,

    /**
     * {@code FLOW_ACT_MANGLE_HDR_TYPE_TCP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_ACT_MANGLE_HDR_TYPE_TCP"
    )
    FLOW_ACT_MANGLE_HDR_TYPE_TCP,

    /**
     * {@code FLOW_ACT_MANGLE_HDR_TYPE_UDP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "FLOW_ACT_MANGLE_HDR_TYPE_UDP"
    )
    FLOW_ACT_MANGLE_HDR_TYPE_UDP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_action_hw_stats"
  )
  public enum flow_action_hw_stats implements Enum<flow_action_hw_stats>, TypedEnum<flow_action_hw_stats, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_ACTION_HW_STATS_IMMEDIATE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_ACTION_HW_STATS_IMMEDIATE"
    )
    FLOW_ACTION_HW_STATS_IMMEDIATE,

    /**
     * {@code FLOW_ACTION_HW_STATS_DELAYED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_ACTION_HW_STATS_DELAYED"
    )
    FLOW_ACTION_HW_STATS_DELAYED,

    /**
     * {@code FLOW_ACTION_HW_STATS_ANY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_ACTION_HW_STATS_ANY"
    )
    FLOW_ACTION_HW_STATS_ANY,

    /**
     * {@code FLOW_ACTION_HW_STATS_DISABLED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_ACTION_HW_STATS_DISABLED"
    )
    FLOW_ACTION_HW_STATS_DISABLED,

    /**
     * {@code FLOW_ACTION_HW_STATS_DONT_CARE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "FLOW_ACTION_HW_STATS_DONT_CARE"
    )
    FLOW_ACTION_HW_STATS_DONT_CARE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_action_cookie"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_action_cookie extends Struct {
    public @Unsigned int cookie_len;

    public char @Size(0) [] cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_action_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_action_entry extends Struct {
    public flow_action_id id;

    public @Unsigned int hw_index;

    public @Unsigned long cookie;

    public @Unsigned long miss_cookie;

    public flow_action_hw_stats hw_stats;

    public @OriginalName("action_destr") Ptr<?> destructor;

    public Ptr<?> destructor_priv;

    @InlineUnion(50977)
    public @Unsigned int chain_index;

    @InlineUnion(50977)
    public Ptr<net_device> dev;

    @InlineUnion(50977)
    public vlan_of_anon_member_of_flow_action_entry vlan;

    @InlineUnion(50977)
    public vlan_push_eth_of_anon_member_of_flow_action_entry vlan_push_eth;

    @InlineUnion(50977)
    public mangle_of_anon_member_of_flow_action_entry mangle;

    @InlineUnion(50977)
    public Ptr<ip_tunnel_info> tunnel;

    @InlineUnion(50977)
    public @Unsigned int csum_flags;

    @InlineUnion(50977)
    public @Unsigned int mark;

    @InlineUnion(50977)
    public @Unsigned short ptype;

    @InlineUnion(50977)
    public @Unsigned short rx_queue;

    @InlineUnion(50977)
    public @Unsigned int priority;

    @InlineUnion(50977)
    public queue_of_anon_member_of_flow_action_entry queue;

    @InlineUnion(50977)
    public sample_of_anon_member_of_flow_action_entry sample;

    @InlineUnion(50977)
    public police_of_anon_member_of_flow_action_entry police;

    @InlineUnion(50977)
    public ct_of_anon_member_of_flow_action_entry ct;

    @InlineUnion(50977)
    public ct_metadata_of_anon_member_of_flow_action_entry ct_metadata;

    @InlineUnion(50977)
    public mpls_push_of_anon_member_of_flow_action_entry mpls_push;

    @InlineUnion(50977)
    public mpls_pop_of_anon_member_of_flow_action_entry mpls_pop;

    @InlineUnion(50977)
    public mpls_mangle_of_anon_member_of_flow_action_entry mpls_mangle;

    @InlineUnion(50977)
    public gate_of_anon_member_of_flow_action_entry gate;

    @InlineUnion(50977)
    public pppoe_of_anon_member_of_flow_action_entry pppoe;

    public Ptr<flow_action_cookie> user_cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_action extends Struct {
    public @Unsigned int num_entries;

    public flow_action_entry @Size(0) [] entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_rule"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_rule extends Struct {
    public flow_match match;

    public flow_action action;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_stats extends Struct {
    public @Unsigned long pkts;

    public @Unsigned long bytes;

    public @Unsigned long drops;

    public @Unsigned long lastused;

    public flow_action_hw_stats used_hw_stats;

    public boolean used_hw_stats_valid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_cls_command"
  )
  public enum flow_cls_command implements Enum<flow_cls_command>, TypedEnum<flow_cls_command, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_CLS_REPLACE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_CLS_REPLACE"
    )
    FLOW_CLS_REPLACE,

    /**
     * {@code FLOW_CLS_DESTROY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_CLS_DESTROY"
    )
    FLOW_CLS_DESTROY,

    /**
     * {@code FLOW_CLS_STATS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_CLS_STATS"
    )
    FLOW_CLS_STATS,

    /**
     * {@code FLOW_CLS_TMPLT_CREATE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_CLS_TMPLT_CREATE"
    )
    FLOW_CLS_TMPLT_CREATE,

    /**
     * {@code FLOW_CLS_TMPLT_DESTROY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_CLS_TMPLT_DESTROY"
    )
    FLOW_CLS_TMPLT_DESTROY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_cls_common_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_cls_common_offload extends Struct {
    public @Unsigned int chain_index;

    public @Unsigned @OriginalName("__be16") short protocol;

    public @Unsigned int prio;

    public boolean skip_sw;

    public Ptr<netlink_ext_ack> extack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_cls_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_cls_offload extends Struct {
    public flow_cls_common_offload common;

    public flow_cls_command command;

    public boolean use_act_stats;

    public @Unsigned long cookie;

    public Ptr<flow_rule> rule;

    public flow_stats stats;

    public @Unsigned int classid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_vlan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_vlan extends Struct {
    @InlineUnion(51104)
    public anon_member_of_anon_member_of_flow_dissector_key_vlan anon0$0;

    @InlineUnion(51104)
    public @Unsigned @OriginalName("__be16") short vlan_tci;

    public @Unsigned @OriginalName("__be16") short vlan_tpid;

    public @Unsigned @OriginalName("__be16") short vlan_eth_type;

    public @Unsigned short padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ipv4_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ipv4_addrs extends Struct {
    public @Unsigned @OriginalName("__be32") int src;

    public @Unsigned @OriginalName("__be32") int dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ipv6_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ipv6_addrs extends Struct {
    public in6_addr src;

    public in6_addr dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_arp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_arp extends Struct {
    public @Unsigned int sip;

    public @Unsigned int tip;

    public char op;

    public char @Size(6) [] sha;

    public char @Size(6) [] tha;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ports"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ports extends Struct {
    @InlineUnion(51110)
    public @Unsigned @OriginalName("__be32") int ports;

    @InlineUnion(51110)
    public anon_member_of_anon_member_of_flow_dissector_key_ports anon0$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_eth_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_eth_addrs extends Struct {
    public char @Size(6) [] dst;

    public char @Size(6) [] src;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_tcp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_tcp extends Struct {
    public @Unsigned @OriginalName("__be16") short flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ip"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ip extends Struct {
    public char tos;

    public char ttl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_eth_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_eth_addrs extends Struct {
    public Ptr<flow_dissector_key_eth_addrs> key;

    public Ptr<flow_dissector_key_eth_addrs> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_vlan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_vlan extends Struct {
    public Ptr<flow_dissector_key_vlan> key;

    public Ptr<flow_dissector_key_vlan> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_arp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_arp extends Struct {
    public Ptr<flow_dissector_key_arp> key;

    public Ptr<flow_dissector_key_arp> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ipv4_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ipv4_addrs extends Struct {
    public Ptr<flow_dissector_key_ipv4_addrs> key;

    public Ptr<flow_dissector_key_ipv4_addrs> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ipv6_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ipv6_addrs extends Struct {
    public Ptr<flow_dissector_key_ipv6_addrs> key;

    public Ptr<flow_dissector_key_ipv6_addrs> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ip"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ip extends Struct {
    public Ptr<flow_dissector_key_ip> key;

    public Ptr<flow_dissector_key_ip> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ports"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ports extends Struct {
    public Ptr<flow_dissector_key_ports> key;

    public Ptr<flow_dissector_key_ports> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_tcp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_tcp extends Struct {
    public Ptr<flow_dissector_key_tcp> key;

    public Ptr<flow_dissector_key_tcp> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_dissector_ctrl_flags"
  )
  public enum flow_dissector_ctrl_flags implements Enum<flow_dissector_ctrl_flags>, TypedEnum<flow_dissector_ctrl_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_DIS_IS_FRAGMENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_DIS_IS_FRAGMENT"
    )
    FLOW_DIS_IS_FRAGMENT,

    /**
     * {@code FLOW_DIS_FIRST_FRAG = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_DIS_FIRST_FRAG"
    )
    FLOW_DIS_FIRST_FRAG,

    /**
     * {@code FLOW_DIS_F_TUNNEL_CSUM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_DIS_F_TUNNEL_CSUM"
    )
    FLOW_DIS_F_TUNNEL_CSUM,

    /**
     * {@code FLOW_DIS_F_TUNNEL_DONT_FRAGMENT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "FLOW_DIS_F_TUNNEL_DONT_FRAGMENT"
    )
    FLOW_DIS_F_TUNNEL_DONT_FRAGMENT,

    /**
     * {@code FLOW_DIS_F_TUNNEL_OAM = 16}
     */
    @EnumMember(
        value = 16L,
        name = "FLOW_DIS_F_TUNNEL_OAM"
    )
    FLOW_DIS_F_TUNNEL_OAM,

    /**
     * {@code FLOW_DIS_F_TUNNEL_CRIT_OPT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "FLOW_DIS_F_TUNNEL_CRIT_OPT"
    )
    FLOW_DIS_F_TUNNEL_CRIT_OPT,

    /**
     * {@code FLOW_DIS_ENCAPSULATION = 64}
     */
    @EnumMember(
        value = 64L,
        name = "FLOW_DIS_ENCAPSULATION"
    )
    FLOW_DIS_ENCAPSULATION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_dissect_ret"
  )
  public enum flow_dissect_ret implements Enum<flow_dissect_ret>, TypedEnum<flow_dissect_ret, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_DISSECT_RET_OUT_GOOD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_DISSECT_RET_OUT_GOOD"
    )
    FLOW_DISSECT_RET_OUT_GOOD,

    /**
     * {@code FLOW_DISSECT_RET_OUT_BAD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_DISSECT_RET_OUT_BAD"
    )
    FLOW_DISSECT_RET_OUT_BAD,

    /**
     * {@code FLOW_DISSECT_RET_PROTO_AGAIN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_DISSECT_RET_PROTO_AGAIN"
    )
    FLOW_DISSECT_RET_PROTO_AGAIN,

    /**
     * {@code FLOW_DISSECT_RET_IPPROTO_AGAIN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_DISSECT_RET_IPPROTO_AGAIN"
    )
    FLOW_DISSECT_RET_IPPROTO_AGAIN,

    /**
     * {@code FLOW_DISSECT_RET_CONTINUE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_DISSECT_RET_CONTINUE"
    )
    FLOW_DISSECT_RET_CONTINUE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_tags"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_tags extends Struct {
    public @Unsigned int flow_label;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_mpls_lse"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_mpls_lse extends Struct {
    public @Unsigned int mpls_ttl;

    public @Unsigned int mpls_bos;

    public @Unsigned int mpls_tc;

    public @Unsigned int mpls_label;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_mpls"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_mpls extends Struct {
    public flow_dissector_mpls_lse @Size(7) [] ls;

    public char used_lses;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_enc_opts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_enc_opts extends Struct {
    public char @Size(255) [] data;

    public char len;

    public @Unsigned int dst_opt_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_keyid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_keyid extends Struct {
    public @Unsigned @OriginalName("__be32") int keyid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_tipc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_tipc extends Struct {
    public @Unsigned @OriginalName("__be32") int key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_addrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_addrs extends Struct {
    @InlineUnion(57448)
    public flow_dissector_key_ipv4_addrs v4addrs;

    @InlineUnion(57448)
    public flow_dissector_key_ipv6_addrs v6addrs;

    @InlineUnion(57448)
    public flow_dissector_key_tipc tipckey;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ports_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ports_range extends Struct {
    @InlineUnion(57451)
    public flow_dissector_key_ports tp;

    @InlineUnion(57451)
    public anon_member_of_anon_member_of_flow_dissector_key_ports_range anon0$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_icmp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_icmp extends Struct {
    public anon_member_of_flow_dissector_key_icmp anon0;

    public @Unsigned short id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_meta extends Struct {
    public int ingress_ifindex;

    public @Unsigned short ingress_iftype;

    public char l2_miss;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ct extends Struct {
    public @Unsigned short ct_state;

    public @Unsigned short ct_zone;

    public @Unsigned int ct_mark;

    public @Unsigned int @Size(4) [] ct_labels;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_hash extends Struct {
    public @Unsigned int hash;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_num_of_vlans"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_num_of_vlans extends Struct {
    public char num_of_vlans;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_pppoe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_pppoe extends Struct {
    public @Unsigned @OriginalName("__be16") short session_id;

    public @Unsigned @OriginalName("__be16") short ppp_proto;

    public @Unsigned @OriginalName("__be16") short type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_l2tpv3"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_l2tpv3 extends Struct {
    public @Unsigned @OriginalName("__be32") int session_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_ipsec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_ipsec extends Struct {
    public @Unsigned @OriginalName("__be32") int spi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key_cfm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key_cfm extends Struct {
    public char mdl_ver;

    public char opcode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_dissector_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_dissector_key extends Struct {
    public flow_dissector_key_id key_id;

    public @Unsigned long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_keys"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_keys extends Struct {
    public flow_dissector_key_control control;

    public flow_dissector_key_basic basic;

    public flow_dissector_key_tags tags;

    public flow_dissector_key_vlan vlan;

    public flow_dissector_key_vlan cvlan;

    public flow_dissector_key_keyid keyid;

    public flow_dissector_key_ports ports;

    public flow_dissector_key_icmp icmp;

    public flow_dissector_key_addrs addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_keys_digest"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_keys_digest extends Struct {
    public char @Size(16) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct _flow_keys_digest_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class _flow_keys_digest_data extends Struct {
    public @Unsigned @OriginalName("__be16") short n_proto;

    public char ip_proto;

    public char padding;

    public @Unsigned @OriginalName("__be32") int ports;

    public @Unsigned @OriginalName("__be32") int src;

    public @Unsigned @OriginalName("__be32") int dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_meta"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_meta extends Struct {
    public Ptr<flow_dissector_key_meta> key;

    public Ptr<flow_dissector_key_meta> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_basic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_basic extends Struct {
    public Ptr<flow_dissector_key_basic> key;

    public Ptr<flow_dissector_key_basic> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_control"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_control extends Struct {
    public Ptr<flow_dissector_key_control> key;

    public Ptr<flow_dissector_key_control> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ports_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ports_range extends Struct {
    public Ptr<flow_dissector_key_ports_range> key;

    public Ptr<flow_dissector_key_ports_range> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_icmp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_icmp extends Struct {
    public Ptr<flow_dissector_key_icmp> key;

    public Ptr<flow_dissector_key_icmp> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ipsec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ipsec extends Struct {
    public Ptr<flow_dissector_key_ipsec> key;

    public Ptr<flow_dissector_key_ipsec> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_mpls"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_mpls extends Struct {
    public Ptr<flow_dissector_key_mpls> key;

    public Ptr<flow_dissector_key_mpls> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_enc_keyid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_enc_keyid extends Struct {
    public Ptr<flow_dissector_key_keyid> key;

    public Ptr<flow_dissector_key_keyid> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_enc_opts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_enc_opts extends Struct {
    public Ptr<flow_dissector_key_enc_opts> key;

    public Ptr<flow_dissector_key_enc_opts> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_ct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_ct extends Struct {
    public Ptr<flow_dissector_key_ct> key;

    public Ptr<flow_dissector_key_ct> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_pppoe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_pppoe extends Struct {
    public Ptr<flow_dissector_key_pppoe> key;

    public Ptr<flow_dissector_key_pppoe> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_match_l2tpv3"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_match_l2tpv3 extends Struct {
    public Ptr<flow_dissector_key_l2tpv3> key;

    public Ptr<flow_dissector_key_l2tpv3> mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_block_command"
  )
  public enum flow_block_command implements Enum<flow_block_command>, TypedEnum<flow_block_command, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_BLOCK_BIND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_BLOCK_BIND"
    )
    FLOW_BLOCK_BIND,

    /**
     * {@code FLOW_BLOCK_UNBIND = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_BLOCK_UNBIND"
    )
    FLOW_BLOCK_UNBIND
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum flow_block_binder_type"
  )
  public enum flow_block_binder_type implements Enum<flow_block_binder_type>, TypedEnum<flow_block_binder_type, java.lang. @Unsigned Integer> {
    /**
     * {@code FLOW_BLOCK_BINDER_TYPE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "FLOW_BLOCK_BINDER_TYPE_UNSPEC"
    )
    FLOW_BLOCK_BINDER_TYPE_UNSPEC,

    /**
     * {@code FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS"
    )
    FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS,

    /**
     * {@code FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS"
    )
    FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS,

    /**
     * {@code FLOW_BLOCK_BINDER_TYPE_RED_EARLY_DROP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "FLOW_BLOCK_BINDER_TYPE_RED_EARLY_DROP"
    )
    FLOW_BLOCK_BINDER_TYPE_RED_EARLY_DROP,

    /**
     * {@code FLOW_BLOCK_BINDER_TYPE_RED_MARK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "FLOW_BLOCK_BINDER_TYPE_RED_MARK"
    )
    FLOW_BLOCK_BINDER_TYPE_RED_MARK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_block_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_block_offload extends Struct {
    public flow_block_command command;

    public flow_block_binder_type binder_type;

    public boolean block_shared;

    public boolean unlocked_driver_cb;

    public Ptr<net> net;

    public Ptr<flow_block> block;

    public list_head cb_list;

    public Ptr<list_head> driver_block_list;

    public Ptr<netlink_ext_ack> extack;

    public Ptr<Qdisc> sch;

    public Ptr<list_head> cb_list_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_block_indr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_block_indr extends Struct {
    public list_head list;

    public Ptr<net_device> dev;

    public Ptr<Qdisc> sch;

    public flow_block_binder_type binder_type;

    public Ptr<?> data;

    public Ptr<?> cb_priv;

    public Ptr<?> cleanup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_block_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_block_cb extends Struct {
    public list_head driver_list;

    public list_head list;

    public Ptr<?> cb;

    public Ptr<?> cb_ident;

    public Ptr<?> cb_priv;

    public Ptr<?> release;

    public flow_block_indr indr;

    public @Unsigned int refcnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_offload_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_offload_action extends Struct {
    public Ptr<netlink_ext_ack> extack;

    public offload_act_command command;

    public flow_action_id id;

    public @Unsigned int index;

    public @Unsigned long cookie;

    public flow_stats stats;

    public flow_action action;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_indr_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_indr_dev extends Struct {
    public list_head list;

    public Ptr<?> cb;

    public Ptr<?> cb_priv;

    public @OriginalName("refcount_t") refcount_struct refcnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct flow_indir_dev_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class flow_indir_dev_info extends Struct {
    public Ptr<?> data;

    public Ptr<net_device> dev;

    public Ptr<Qdisc> sch;

    public tc_setup_type type;

    public Ptr<?> cleanup;

    public list_head list;

    public flow_block_command command;

    public flow_block_binder_type binder_type;

    public Ptr<list_head> cb_list;
  }
}
