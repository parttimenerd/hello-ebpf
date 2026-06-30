/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
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
 * Generated class for BPF runtime types that start with ia32
 */
@java.lang.SuppressWarnings("unused")
public final class Ia32Definitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_epoll_pwait((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_epoll_pwait(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_epoll_pwait2((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_epoll_pwait2(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_execve((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_execve(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_execveat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_execveat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fadvise64_64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fadvise64_64(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fanotify_mark((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fanotify_mark(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fcntl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fcntl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fcntl64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fcntl64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fstatfs((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fstatfs(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_fstatfs64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_fstatfs64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ftruncate((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ftruncate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_get_robust_list((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_get_robust_list(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_getdents((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_getdents(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_getitimer((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_getitimer(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_getrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_getrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_getrusage((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_getrusage(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_getsockopt((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_getsockopt(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_gettimeofday((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_gettimeofday(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_clone((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_clone(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_fstat64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_fstat64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_fstatat64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_fstatat64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_lstat64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_lstat64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_mmap((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_mmap(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ia32_stat64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ia32_stat64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_io_pgetevents((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_io_pgetevents(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_io_pgetevents_time64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_io_pgetevents_time64(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_io_setup((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_io_setup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_io_submit((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_io_submit(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ioctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ioctl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ipc((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ipc(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_kexec_load((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_kexec_load(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_keyctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_keyctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_lseek((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_lseek(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_mq_getsetattr((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_mq_getsetattr(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_mq_notify((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_mq_notify(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_mq_open((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_mq_open(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_msgctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_msgctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_msgrcv((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_msgrcv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_msgsnd((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_msgsnd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_newfstat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_newfstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_newfstatat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_newfstatat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_newlstat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_newlstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_newstat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_newstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_getrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_getrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_msgctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_msgctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_readdir((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_readdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_select((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_select(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_semctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_semctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_old_shmctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_old_shmctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_open((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_open(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_open_by_handle_at((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_open_by_handle_at(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_openat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_openat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ppoll_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ppoll_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ppoll_time64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ppoll_time64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_preadv((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_preadv(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_preadv2((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_preadv2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_preadv64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_preadv64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_preadv64v2((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_preadv64v2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_process_vm_readv((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_process_vm_readv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_process_vm_writev((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_process_vm_writev(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pselect6_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pselect6_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pselect6_time64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pselect6_time64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ptrace((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ptrace(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pwritev((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pwritev(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pwritev2((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pwritev2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pwritev64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pwritev64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_pwritev64v2((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_pwritev64v2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_recv((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_recv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_recvfrom((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_recvfrom(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_recvmmsg_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_recvmmsg_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_recvmmsg_time64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_recvmmsg_time64(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_recvmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_recvmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigaction((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigaction(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigpending((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigpending(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigprocmask((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigprocmask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigqueueinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigqueueinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigsuspend((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigsuspend(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigtimedwait_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigtimedwait_time32(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_sigtimedwait_time64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_sigtimedwait_time64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_rt_tgsigqueueinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_rt_tgsigqueueinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_s390_ipc((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_s390_ipc(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sched_getaffinity((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sched_getaffinity(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sched_setaffinity((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sched_setaffinity(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_select((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_select(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_semctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_semctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sendfile((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sendfile(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sendfile64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sendfile64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sendmmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sendmmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sendmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sendmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_set_robust_list((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_set_robust_list(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_setitimer((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_setitimer(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_setrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_setrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_setsockopt((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_setsockopt(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_settimeofday((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_settimeofday(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_shmat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_shmat(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_shmctl((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_shmctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sigaction((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sigaction(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sigaltstack((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sigaltstack(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_signalfd((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_signalfd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_signalfd4((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_signalfd4(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sigpending((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sigpending(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sigprocmask((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sigprocmask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_socketcall((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_socketcall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_statfs((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_statfs(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_statfs64((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_statfs64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_sysinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_sysinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_timer_create((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_timer_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_times((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_times(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_truncate((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_truncate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_ustat((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_ustat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_wait4((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_wait4(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_compat_sys_waitid((const struct pt_regs *)$arg1)")
  public static long __ia32_compat_sys_waitid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_accept((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_accept(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_accept4((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_accept4(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_access((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_access(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_acct((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_acct(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_add_key((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_add_key(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_adjtimex((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_adjtimex(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_adjtimex_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_adjtimex_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_alarm((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_alarm(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_arch_prctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_arch_prctl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_bind((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_bind(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_bpf((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_bpf(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_brk((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_brk(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_cachestat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_cachestat(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_capget((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_capget(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_capset((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_capset(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_chdir((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_chdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_chmod((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_chmod(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_chown((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_chown(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_chown16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_chown16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_chroot((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_chroot(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_adjtime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_adjtime(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_adjtime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_adjtime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_getres((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_getres(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_getres_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_getres_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_gettime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_gettime(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_gettime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_gettime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_nanosleep((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_nanosleep(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_nanosleep_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_nanosleep_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_settime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_settime(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clock_settime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clock_settime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clone((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clone(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_clone3((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_clone3(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_close((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_close(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_close_range((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_close_range(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_connect((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_connect(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_copy_file_range((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_copy_file_range(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_creat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_creat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_delete_module((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_delete_module(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_dup((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_dup(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_dup2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_dup2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_dup3((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_dup3(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_create((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_create1((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_create1(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_ctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_ctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_pwait((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_pwait(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_pwait2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_pwait2(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_epoll_wait((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_epoll_wait(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_eventfd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_eventfd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_eventfd2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_eventfd2(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_execve((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_execve(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_execveat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_execveat(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_exit((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_exit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_exit_group((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_exit_group(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_faccessat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_faccessat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_faccessat2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_faccessat2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fadvise64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fadvise64(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fadvise64_64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fadvise64_64(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fallocate((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fallocate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fanotify_init((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fanotify_init(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fanotify_mark((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fanotify_mark(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchdir((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchmod((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchmod(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchmodat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchmodat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchmodat2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchmodat2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchown((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchown(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchown16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchown16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fchownat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fchownat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fcntl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fcntl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fdatasync((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fdatasync(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fgetxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fgetxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_file_getattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_file_getattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_file_setattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_file_setattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_finit_module((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_finit_module(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_flistxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_flistxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_flock((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_flock(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fremovexattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fremovexattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fsconfig((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fsconfig(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fsetxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fsetxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fsmount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fsmount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fsopen((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fsopen(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fspick((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fspick(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fstat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fstatfs((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fstatfs(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fstatfs64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fstatfs64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_fsync((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_fsync(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ftruncate((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ftruncate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex_requeue((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex_requeue(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex_wait((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex_wait(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex_waitv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex_waitv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futex_wake((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futex_wake(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futimesat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futimesat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_futimesat_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_futimesat_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_get_mempolicy((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_get_mempolicy(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_get_robust_list((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_get_robust_list(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_get_thread_area((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_get_thread_area(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getcpu((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getcpu(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getcwd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getcwd(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getdents((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getdents(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getdents64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getdents64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getegid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getegid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_geteuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_geteuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getgid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getgroups((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getgroups(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getgroups16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getgroups16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_gethostname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_gethostname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getitimer((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getitimer(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getpeername((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getpeername(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getpgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getpgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getpriority((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getpriority(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getrandom((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getrandom(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getresgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getresgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getresgid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getresgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getresuid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getresuid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getresuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getresuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getrusage((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getrusage(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getsid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getsid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getsockname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getsockname(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getsockopt((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getsockopt(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_gettimeofday((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_gettimeofday(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_getxattrat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_getxattrat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_fadvise64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_fadvise64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_fadvise64_64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_fadvise64_64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_fallocate((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_fallocate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_ftruncate64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_ftruncate64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_pread64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_pread64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_pwrite64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_pwrite64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_readahead((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_readahead(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_sync_file_range((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_sync_file_range(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ia32_truncate64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ia32_truncate64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_init_module((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_init_module(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_inotify_add_watch((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_inotify_add_watch(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_inotify_init((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_inotify_init(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_inotify_init1((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_inotify_init1(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_inotify_rm_watch((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_inotify_rm_watch(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_cancel((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_cancel(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_destroy((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_destroy(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_getevents((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_getevents(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_getevents_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_getevents_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_pgetevents((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_pgetevents(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_pgetevents_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_pgetevents_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_setup((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_setup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_submit((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_submit(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_uring_enter((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_uring_enter(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_uring_register((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_uring_register(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_io_uring_setup((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_io_uring_setup(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ioctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ioctl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ioperm((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ioperm(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_iopl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_iopl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ioprio_get((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ioprio_get(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ioprio_set((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ioprio_set(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ipc((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ipc(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_kcmp((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_kcmp(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_kexec_file_load((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_kexec_file_load(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_kexec_load((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_kexec_load(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_keyctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_keyctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_kill((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_kill(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_landlock_add_rule((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_landlock_add_rule(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_landlock_create_ruleset((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_landlock_create_ruleset(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_landlock_restrict_self((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_landlock_restrict_self(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lchown((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lchown(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lchown16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lchown16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lgetxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lgetxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_link((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_link(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_linkat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_linkat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_listen((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_listen(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_listmount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_listmount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_listxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_listxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_listxattrat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_listxattrat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_llistxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_llistxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_llseek((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_llseek(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lremovexattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lremovexattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lseek((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lseek(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lsetxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lsetxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lsm_get_self_attr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lsm_get_self_attr(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lsm_list_modules((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lsm_list_modules(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lsm_set_self_attr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lsm_set_self_attr(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_lstat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_lstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_madvise((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_madvise(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_map_shadow_stack((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_map_shadow_stack(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mbind((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mbind(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_membarrier((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_membarrier(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_memfd_create((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_memfd_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_memfd_secret((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_memfd_secret(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_migrate_pages((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_migrate_pages(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mincore((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mincore(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mkdir((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mkdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mkdirat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mkdirat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mknod((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mknod(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mknodat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mknodat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mlock((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mlock(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mlock2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mlock2(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mlockall((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mlockall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mmap((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mmap(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mmap_pgoff((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mmap_pgoff(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_modify_ldt((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_modify_ldt(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mount_setattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mount_setattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_move_mount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_move_mount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_move_pages((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_move_pages(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mprotect((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mprotect(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_getsetattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_getsetattr(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_notify((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_notify(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_open((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_open(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_timedreceive((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_timedreceive(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_timedreceive_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_timedreceive_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_timedsend((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_timedsend(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_timedsend_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_timedsend_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mq_unlink((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mq_unlink(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mremap((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mremap(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_mseal((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_mseal(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_msgctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_msgctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_msgget((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_msgget(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_msgrcv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_msgrcv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_msgsnd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_msgsnd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_msync((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_msync(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_munlock((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_munlock(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_munlockall((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_munlockall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_munmap((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_munmap(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_name_to_handle_at((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_name_to_handle_at(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_nanosleep((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_nanosleep(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_nanosleep_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_nanosleep_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_newfstat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_newfstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_newfstatat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_newfstatat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_newlstat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_newlstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_newstat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_newstat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_newuname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_newuname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_nice((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_nice(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_old_getrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_old_getrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_old_msgctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_old_msgctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_old_readdir((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_old_readdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_old_semctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_old_semctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_old_shmctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_old_shmctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_oldumount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_oldumount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_olduname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_olduname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_open((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_open(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_open_by_handle_at((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_open_by_handle_at(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_open_tree((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_open_tree(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_open_tree_attr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_open_tree_attr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_openat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_openat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_openat2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_openat2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pciconfig_iobase((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pciconfig_iobase(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pciconfig_read((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pciconfig_read(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pciconfig_write((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pciconfig_write(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_perf_event_open((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_perf_event_open(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_personality((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_personality(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pidfd_getfd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pidfd_getfd(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pidfd_open((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pidfd_open(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pidfd_send_signal((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pidfd_send_signal(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pipe((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pipe(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pipe2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pipe2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pivot_root((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pivot_root(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pkey_alloc((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pkey_alloc(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pkey_free((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pkey_free(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pkey_mprotect((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pkey_mprotect(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_poll((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_poll(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ppoll((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ppoll(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ppoll_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ppoll_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_prctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_prctl(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pread64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pread64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_preadv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_preadv(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_preadv2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_preadv2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_prlimit64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_prlimit64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_process_madvise((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_process_madvise(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_process_mrelease((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_process_mrelease(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_process_vm_readv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_process_vm_readv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_process_vm_writev((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_process_vm_writev(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pselect6((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pselect6(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pselect6_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pselect6_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ptrace((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ptrace(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pwrite64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pwrite64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pwritev((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pwritev(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_pwritev2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_pwritev2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_quotactl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_quotactl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_quotactl_fd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_quotactl_fd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_read((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_read(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_readahead((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_readahead(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_readlink((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_readlink(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_readlinkat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_readlinkat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_readv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_readv(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_reboot((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_reboot(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_recv((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_recv(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_recvfrom((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_recvfrom(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_recvmmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_recvmmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_recvmmsg_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_recvmmsg_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_recvmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_recvmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_remap_file_pages((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_remap_file_pages(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_removexattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_removexattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_removexattrat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_removexattrat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rename((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rename(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_renameat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_renameat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_renameat2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_renameat2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_request_key((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_request_key(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rmdir((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rmdir(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rseq((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rseq(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigaction((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigaction(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigpending((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigpending(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigprocmask((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigprocmask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigqueueinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigqueueinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigsuspend((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigsuspend(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigtimedwait((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigtimedwait(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_sigtimedwait_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_sigtimedwait_time32(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rt_tgsigqueueinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rt_tgsigqueueinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_rtas((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_rtas(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_s390_ipc((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_s390_ipc(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_s390_pci_mmio_read((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_s390_pci_mmio_read(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_s390_pci_mmio_write((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_s390_pci_mmio_write(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_get_priority_max((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_get_priority_max(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_get_priority_min((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_get_priority_min(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_getaffinity((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_getaffinity(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_getattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_getattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_getparam((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_getparam(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_getscheduler((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_getscheduler(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_rr_get_interval((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_rr_get_interval(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_rr_get_interval_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_rr_get_interval_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_setaffinity((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_setaffinity(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_setattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_setattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_setparam((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_setparam(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sched_setscheduler((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sched_setscheduler(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_seccomp((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_seccomp(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_select((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_select(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_semctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_semctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_semget((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_semget(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_semop((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_semop(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_semtimedop((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_semtimedop(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_semtimedop_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_semtimedop_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_send((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_send(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sendfile((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sendfile(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sendfile64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sendfile64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sendmmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sendmmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sendmsg((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sendmsg(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sendto((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sendto(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_set_mempolicy((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_set_mempolicy(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_set_mempolicy_home_node((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_set_mempolicy_home_node(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_set_robust_list((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_set_robust_list(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_set_thread_area((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_set_thread_area(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_set_tid_address((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_set_tid_address(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setdomainname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setdomainname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setfsgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setfsgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setfsgid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setfsgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setfsuid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setfsuid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setfsuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setfsuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setgid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setgroups((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setgroups(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setgroups16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setgroups16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sethostname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sethostname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setitimer((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setitimer(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setns((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setns(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setpgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setpgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setpriority((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setpriority(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setregid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setregid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setregid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setregid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setresgid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setresgid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setresgid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setresgid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setresuid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setresuid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setresuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setresuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setreuid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setreuid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setreuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setreuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setrlimit((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setrlimit(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setsockopt((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setsockopt(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_settimeofday((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_settimeofday(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setuid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setuid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setuid16((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setuid16(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setxattr((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setxattr(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_setxattrat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_setxattrat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sgetmask((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sgetmask(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_shmat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_shmat(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_shmctl((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_shmctl(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_shmdt((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_shmdt(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_shmget((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_shmget(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_shutdown((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_shutdown(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sigaltstack((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sigaltstack(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_signal((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_signal(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_signalfd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_signalfd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_signalfd4((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_signalfd4(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sigpending((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sigpending(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sigprocmask((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sigprocmask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sigsuspend((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sigsuspend(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_socket((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_socket(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_socketcall((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_socketcall(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_socketpair((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_socketpair(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_splice((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_splice(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_spu_create((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_spu_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_spu_run((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_spu_run(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ssetmask((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ssetmask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_stat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_stat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_statfs((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_statfs(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_statfs64((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_statfs64(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_statmount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_statmount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_statx((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_statx(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_stime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_stime(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_stime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_stime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_subpage_prot((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_subpage_prot(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_swapoff((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_swapoff(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_swapon((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_swapon(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_symlink((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_symlink(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_symlinkat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_symlinkat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sync_file_range((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sync_file_range(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sync_file_range2((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sync_file_range2(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_syncfs((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_syncfs(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sysfs((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sysfs(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_sysinfo((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_sysinfo(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_syslog((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_syslog(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_tee((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_tee(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_tgkill((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_tgkill(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_time((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_time(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_create((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_delete((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_delete(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_getoverrun((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_getoverrun(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_gettime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_gettime(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_gettime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_gettime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_settime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_settime(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timer_settime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timer_settime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timerfd_create((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timerfd_create(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timerfd_gettime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timerfd_gettime(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timerfd_gettime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timerfd_gettime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timerfd_settime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timerfd_settime(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_timerfd_settime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_timerfd_settime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_times((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_times(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_tkill((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_tkill(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_truncate((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_truncate(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_umask((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_umask(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_umount((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_umount(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_uname((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_uname(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_unlink((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_unlink(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_unlinkat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_unlinkat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_unshare((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_unshare(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_uretprobe((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_uretprobe(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_uselib((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_uselib(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_userfaultfd((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_userfaultfd(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_ustat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_ustat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utime((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utime(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utime32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utime32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utimensat((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utimensat(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utimensat_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utimensat_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utimes((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utimes(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_utimes_time32((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_utimes_time32(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_vm86((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_vm86(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_vm86old((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_vm86old(Ptr<pt_regs> __unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_vmsplice((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_vmsplice(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_wait4((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_wait4(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_waitid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_waitid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_waitpid((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_waitpid(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_write((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_write(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ia32_sys_writev((const struct pt_regs *)$arg1)")
  public static long __ia32_sys_writev(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long ia32_arch_ptrace(Ptr<task_struct> child,
      @OriginalName("compat_long_t") int request,
      @Unsigned @OriginalName("compat_ulong_t") int caddr,
      @Unsigned @OriginalName("compat_ulong_t") int cdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ia32_binfmt_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ia32_classify_syscall(@Unsigned int syscall) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ia32_emulation_override_cmdline(String arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ia32_restore_sigcontext(Ptr<pt_regs> regs, Ptr<sigcontext_32> usc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ia32_setup_frame(Ptr<ksignal> ksig, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ia32_setup_rt_frame(Ptr<ksignal> ksig, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ia32_sys_call((const struct pt_regs *)$arg1, $arg2)")
  public static long ia32_sys_call(Ptr<pt_regs> regs, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }
}
