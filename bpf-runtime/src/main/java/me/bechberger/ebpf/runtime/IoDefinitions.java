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
 * Generated class for BPF runtime types that start with io
 */
@java.lang.SuppressWarnings("unused")
public final class IoDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_account_mem(Ptr<user_struct> user, @Unsigned long nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __io_alloc_req_refill(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_arm_poll_handler(Ptr<io_kiocb> req, Ptr<io_poll> poll,
      Ptr<io_poll_table> ipt, @Unsigned @OriginalName("__poll_t") int mask,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_async_cancel(Ptr<io_cancel_data> cd, Ptr<io_uring_task> tctx,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_close_fixed(Ptr<io_ring_ctx> ctx, @Unsigned int issue_flags,
      @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_commit_cqring_flush(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_complete_rw_common(Ptr<io_kiocb> req, long res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_cqring_overflow_flush(Ptr<io_ring_ctx> ctx, boolean dying) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_fallback_tw(Ptr<llist_node> node, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_fixed_fd_install(Ptr<io_ring_ctx> ctx, Ptr<file> file,
      @Unsigned int file_slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __io_futex_cancel(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_getxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int __io_getxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_import_rw_buffer(int ddir, Ptr<io_kiocb> req, Ptr<io_async_rw> io,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_issue_sqe($arg1, $arg2, (const struct io_issue_def *)$arg3)")
  public static int __io_issue_sqe(Ptr<io_kiocb> req, @Unsigned int issue_flags,
      Ptr<io_issue_def> def) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_msg_ring_data(Ptr<io_ring_ctx> target_ctx, Ptr<io_msg> msg,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_napi_add_id(Ptr<io_ring_ctx> ctx, @Unsigned int napi_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_napi_busy_loop(Ptr<io_ring_ctx> ctx, Ptr<io_wait_queue> iowq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_napi_remove_stale(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_openat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int __io_openat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_poll_execute(Ptr<io_kiocb> req, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_prep_rw($arg1, (const struct io_uring_sqe *)$arg2, $arg3)")
  public static int __io_prep_rw(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe, int ddir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int __io_put_kbufs(Ptr<io_kiocb> req, int len, int nbufs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_queue_proc(Ptr<io_poll> poll, Ptr<io_poll_table> pt,
      Ptr<wait_queue_head> head, Ptr<Ptr<io_poll>> poll_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_read(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_register_iowq_aff(Ptr<io_ring_ctx> ctx,
      @OriginalName("cpumask_var_t") Ptr<cpumask> new_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_req_caches_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_req_task_work_add(Ptr<io_kiocb> req, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_run_local_work(Ptr<io_ring_ctx> ctx,
      @OriginalName("io_tw_token_t") io_tw_state tw, int min_events, int max_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_run_local_work_loop(Ptr<Ptr<llist_node>> node,
      @OriginalName("io_tw_token_t") io_tw_state tw, int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_setxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int __io_setxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_sqe_buffers_update(Ptr<io_ring_ctx> ctx, Ptr<io_uring_rsrc_update2> up,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_sqe_files_update(Ptr<io_ring_ctx> ctx, Ptr<io_uring_rsrc_update2> up,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_submit_flush_completions(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_sync_cancel(Ptr<io_uring_task> tctx, Ptr<io_cancel_data> cd, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_timeout_prep($arg1, (const struct io_uring_sqe *)$arg2, $arg3)")
  public static int __io_timeout_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe,
      boolean is_timeout_link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_uring_add_tctx_node(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_uring_add_tctx_node_from_submit(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_uring_cancel(boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__io_uring_cmd_do_in_task($arg1, (void (*)(struct io_uring_cmd*, unsigned int))$arg2, $arg3)")
  public static void __io_uring_cmd_do_in_task(Ptr<io_uring_cmd> ioucmd, Ptr<?> task_work_cb,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_uring_free(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __io_uring_register(Ptr<io_ring_ctx> ctx, @Unsigned int opcode, Ptr<?> arg,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __io_uring_show_fdinfo(Ptr<io_ring_ctx> ctx, Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __io_waitid_cancel(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_accept_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_accept_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_account_mem(Ptr<io_ring_ctx> ctx, @Unsigned long nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_acct_activate_free_worker(Ptr<io_wq_acct> acct) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_acct_cancel_pending_work(Ptr<io_wq> wq, Ptr<io_wq_acct> acct,
      Ptr<io_cb_cancel_data> match) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_acct_for_each_worker($arg1, (_Bool (*)(struct io_worker*, void*))$arg2, $arg3)")
  public static boolean io_acct_for_each_worker(Ptr<io_wq_acct> acct, Ptr<?> func, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_acct_run_queue(Ptr<io_wq_acct> acct) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_activate_pollwq(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_activate_pollwq_cb(Ptr<callback_head> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_add_aux_cqe(Ptr<io_ring_ctx> ctx, @Unsigned long user_data, int res,
      @Unsigned int cflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_alloc_cache_free($arg1, (void (*)(const void*))$arg2)")
  public static void io_alloc_cache_free(Ptr<io_alloc_cache> cache, Ptr<?> free) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_alloc_cache_init(Ptr<io_alloc_cache> cache, @Unsigned int max_nr,
      @Unsigned int size, @Unsigned int init_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_alloc_file_tables(Ptr<io_ring_ctx> ctx, Ptr<io_file_table> table,
      @Unsigned int nr_files) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_mapped_ubuf> io_alloc_imu(Ptr<io_ring_ctx> ctx, int nr_bvecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_kiocb> io_alloc_notif(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_overflow_cqe> io_alloc_ocqe(Ptr<io_ring_ctx> ctx, Ptr<io_cqe> cqe,
      Ptr<io_big_cqe> big_cqe, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_allocate_scq_urings(Ptr<io_ring_ctx> ctx, Ptr<io_uring_params> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_apic_init_mappings() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_apic_print_entries(@Unsigned int apic, @Unsigned int nr_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_apic_set_fixmap(fixed_addresses idx,
      @Unsigned @OriginalName("phys_addr_t") long phys) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_apic_sync(Ptr<irq_pin_list> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char io_apic_unique_id(int idx, char id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_arm_apoll(Ptr<io_kiocb> req, @Unsigned int issue_flags,
      @Unsigned @OriginalName("__poll_t") int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_arm_poll_handler(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_async_buf_func(Ptr<wait_queue_entry> wait, @Unsigned int mode, int sync,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_async_cancel(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_async_cancel_one(Ptr<io_uring_task> tctx, Ptr<io_cancel_data> cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_async_cancel_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_async_cancel_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_async_queue_proc(Ptr<file> file, Ptr<wait_queue_head> head,
      Ptr<poll_table_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_bind_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_bind_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_bitmap_exit(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_bitmap_share(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffer_account_pin(Ptr<io_ring_ctx> ctx, Ptr<Ptr<page>> pages, int nr_pages,
      Ptr<io_mapped_ubuf> imu, Ptr<Ptr<page>> last_hpage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffer_add_list(Ptr<io_ring_ctx> ctx, Ptr<io_buffer_list> bl,
      @Unsigned int bgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_buffer_register_bvec($arg1, $arg2, (void (*)(void*))$arg3, $arg4, $arg5)")
  public static int io_buffer_register_bvec(Ptr<io_uring_cmd> cmd, Ptr<request> rq, Ptr<?> release,
      @Unsigned int index, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> io_buffer_select(Ptr<io_kiocb> req, Ptr<java.lang. @Unsigned Long> len,
      @Unsigned int buf_group, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffer_unregister_bvec(Ptr<io_uring_cmd> cmd, @Unsigned int index,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffer_validate(Ptr<iovec> iov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffers_peek(Ptr<io_kiocb> req, Ptr<buf_sel_arg> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_buffers_select(Ptr<io_kiocb> req, Ptr<buf_sel_arg> arg,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> io_cache_alloc_new(Ptr<io_alloc_cache> cache,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cancel_cb(Ptr<io_wq_work> work, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cancel_ctx_cb(Ptr<io_wq_work> work, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_cancel_remove($arg1, $arg2, $arg3, $arg4, (_Bool (*)(struct io_kiocb*))$arg5)")
  public static int io_cancel_remove(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd,
      @Unsigned int issue_flags, Ptr<hlist_head> list, Ptr<?> cancel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_cancel_remove_all($arg1, $arg2, $arg3, $arg4, (_Bool (*)(struct io_kiocb*))$arg5)")
  public static boolean io_cancel_remove_all(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      Ptr<hlist_head> list, boolean cancel_all, Ptr<?> cancel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cancel_req_match(Ptr<io_kiocb> req, Ptr<io_cancel_data> cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cancel_task_cb(Ptr<io_wq_work> work, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_check_coalesce_buffer(Ptr<Ptr<page>> page_array, int nr_pages,
      Ptr<io_imu_folio_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_check_error(char reason, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_clear_table_tags(Ptr<io_rsrc_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_clone_buffers(Ptr<io_ring_ctx> ctx, Ptr<io_ring_ctx> src_ctx,
      Ptr<io_uring_clone_buffers> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_close_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_close_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_close_queue(Ptr<io_zcrx_ifq> ifq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_cmd_cache_free((const void *)$arg1)")
  public static void io_cmd_cache_free(Ptr<?> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_cmd_poll_multishot(Ptr<io_uring_cmd> cmd, @Unsigned int issue_flags,
      @Unsigned @OriginalName("__poll_t") int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_coalesce_buffer(Ptr<Ptr<Ptr<page>>> pages,
      Ptr<java.lang.Integer> nr_pages, Ptr<io_imu_folio_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_complete_rw(Ptr<kiocb> kiocb, long res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_complete_rw_iopoll(Ptr<kiocb> kiocb, long res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_connect_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_connect_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long io_copy_page(Ptr<io_copy_cache> cc,
      Ptr<page> src_page, @Unsigned int src_offset, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_cq_unlock_post(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cqe_cache_refill(Ptr<io_ring_ctx> ctx, boolean overflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_cqe_overflow(Ptr<io_ring_ctx> ctx, Ptr<io_cqe> cqe,
      Ptr<io_big_cqe> big_cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cqe_overflow_locked(Ptr<io_ring_ctx> ctx, Ptr<io_cqe> cqe,
      Ptr<io_big_cqe> big_cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_cqring_add_overflow(Ptr<io_ring_ctx> ctx, Ptr<io_overflow_cqe> ocqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart io_cqring_min_timer_wakeup(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart io_cqring_timer_wakeup(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_cqring_wait(Ptr<io_ring_ctx> ctx, int min_events, @Unsigned int flags,
      Ptr<ext_arg> ext_arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_create_region(Ptr<io_ring_ctx> ctx, Ptr<io_mapped_region> mr,
      Ptr<io_uring_region_desc> reg, @Unsigned long mmap_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_create_region_mmap_safe(Ptr<io_ring_ctx> ctx, Ptr<io_mapped_region> mr,
      Ptr<io_uring_region_desc> reg, @Unsigned long mmap_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_delay_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_delay_param(String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_destroy_buffers(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_disarm_next(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_do_iopoll(Ptr<io_ring_ctx> ctx, boolean force_nonspin) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_eopnotsupp_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_eopnotsupp_prep(Ptr<io_kiocb> kiocb, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_epoll_ctl(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_epoll_ctl_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_epoll_ctl_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_epoll_wait_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_epoll_wait_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_err_clone_and_map_rq(Ptr<dm_target> ti, Ptr<request> rq,
      Ptr<map_info> map_context, Ptr<Ptr<request>> clone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_err_ctr(Ptr<dm_target> tt, @Unsigned int argc, Ptr<String> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long io_err_dax_direct_access(Ptr<dm_target> ti, @Unsigned long pgoff,
      long nr_pages, dax_access_mode mode, Ptr<Ptr<?>> kaddr, Ptr<java.lang. @Unsigned Long> pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_err_dtr(Ptr<dm_target> tt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_err_io_hints(Ptr<dm_target> ti, Ptr<queue_limits> limits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_err_iterate_devices(Ptr<dm_target> ti,
      @OriginalName("iterate_devices_callout_fn") Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_err_map(Ptr<dm_target> tt, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_err_release_clone_rq(Ptr<request> clone, Ptr<map_info> map_context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_err_report_zones(Ptr<dm_target> ti, Ptr<dm_report_zones_args> args,
      @Unsigned int nr_zones) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_eventfd_do_signal(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_eventfd_free(Ptr<callback_head> rcu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_eventfd_put(Ptr<io_ev_fd> ev_fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_eventfd_register(Ptr<io_ring_ctx> ctx, Ptr<?> arg,
      @Unsigned int eventfd_async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_eventfd_signal(Ptr<io_ring_ctx> ctx, boolean cqe_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_eventfd_unregister(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_fadvise_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_fadvise_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_fallback_req_func(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fallocate(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_fallocate_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_fallocate_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fgetxattr(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_fgetxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_fgetxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> io_file_get_fixed(Ptr<io_kiocb> req, int fd, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("io_req_flags_t") long io_file_get_flags(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> io_file_get_normal(Ptr<io_kiocb> req, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_file_supports_nowait(Ptr<io_kiocb> req,
      @Unsigned @OriginalName("__poll_t") int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_files_update(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_files_update_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_files_update_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_fill_cqe_aux(Ptr<io_ring_ctx> ctx, @Unsigned long user_data, int res,
      @Unsigned int cflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_fill_cqe_aux32(Ptr<io_ring_ctx> ctx, Ptr<io_uring_cqe> src_cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_rsrc_node> io_find_buf_node(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fixed_fd_install(Ptr<io_kiocb> req, @Unsigned int issue_flags,
      Ptr<file> file, @Unsigned int file_slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fixed_fd_remove(Ptr<io_ring_ctx> ctx, @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_flush_killed_timeouts(Ptr<list_head> list, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_flush_timeouts(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_alloc_caches(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_batch_list(Ptr<io_ring_ctx> ctx, Ptr<io_wq_work_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_file_tables(Ptr<io_ring_ctx> ctx, Ptr<io_file_table> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_region(Ptr<io_ring_ctx> ctx, Ptr<io_mapped_region> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_req(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_free_rsrc_node(Ptr<io_ring_ctx> ctx, Ptr<io_rsrc_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fsetxattr(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_fsetxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_fsetxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_fsync(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_fsync_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_fsync_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_ftruncate(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_ftruncate_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_ftruncate_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_futex_cache_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_futex_cache_init(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_futex_cancel(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_futex_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_futex_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_futex_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_futex_remove_all(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_futex_wait(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_futex_wake(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_futex_wake_fn(Ptr<wake_q_head> wake_q, Ptr<futex_q> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_futex_wakev_fn(Ptr<wake_q_head> wake_q, Ptr<futex_q> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_futexv_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_futexv_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_futexv_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_futexv_wait(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_get_ext_arg($arg1, $arg2, (const void *)$arg3, $arg4)")
  public static int io_get_ext_arg(Ptr<io_ring_ctx> ctx, @Unsigned int flags, Ptr<?> argp,
      Ptr<ext_arg> ext_arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_getxattr(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_getxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_getxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<llist_node> io_handle_tw_list(Ptr<llist_node> node,
      Ptr<java.lang. @Unsigned Integer> count, @Unsigned int max_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_idle(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_import_fixed(int ddir, Ptr<iov_iter> iter, Ptr<io_mapped_ubuf> imu,
      @Unsigned long buf_addr, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_import_reg_buf(Ptr<io_kiocb> req, Ptr<iov_iter> iter,
      @Unsigned long buf_addr, @Unsigned long len, int ddir, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_import_reg_vec(int ddir, Ptr<iov_iter> iter, Ptr<io_kiocb> req,
      Ptr<iou_vec> vec, @Unsigned int nr_iovs, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_import_umem(Ptr<io_zcrx_ifq> ifq, Ptr<io_zcrx_mem> mem,
      Ptr<io_uring_zcrx_area_reg> area_reg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_init_fail_req(Ptr<io_kiocb> req, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_init_new_worker(Ptr<io_wq> wq, Ptr<io_wq_acct> acct, Ptr<io_worker> worker,
      Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_init_req($arg1, $arg2, (const struct io_uring_sqe *)$arg3)")
  public static int io_init_req(Ptr<io_ring_ctx> ctx, Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_install_fixed_fd(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_install_fixed_fd_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_install_fixed_fd_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_install_fixed_file(Ptr<io_ring_ctx> ctx, Ptr<file> file,
      @Unsigned int slot_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_iopoll_check(Ptr<io_ring_ctx> ctx, @Unsigned int min_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_iov_buffer_select_prep(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long io_is_busy_show(Ptr<gov_attr_set> attr_set,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_is_busy_store($arg1, (const u8 *)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long io_is_busy_store(Ptr<gov_attr_set> attr_set,
      String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_is_uring_fops(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_issue_sqe(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_kbuf_commit(Ptr<io_kiocb> req, Ptr<io_buffer_list> bl, int len, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_kbuf_drop_legacy(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_kbuf_recycle_legacy(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_kill_timeout(Ptr<io_kiocb> req, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_kill_timeouts(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_link_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_link_skb(Ptr<sk_buff> skb, Ptr<ubuf_info> uarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart io_link_timeout_fn(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_link_timeout_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_link_timeout_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_linkat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_linkat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_linkat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_listen_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_listen_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_madvise_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_madvise_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_manage_buffers_legacy(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_match_task_safe(Ptr<io_kiocb> head, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_mkdirat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_mkdirat_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_mkdirat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_mkdirat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_mapped_region> io_mmap_get_region(Ptr<io_ring_ctx> ctx,
      @OriginalName("loff_t") long pgoff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_move_task_work_from_local(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_async_msghdr> io_msg_alloc_async(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_msg_install_complete(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_msg_ring(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_msg_ring_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_msg_ring_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_msg_ring_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_msg_tw_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_msg_tw_fd_complete(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_napi_busy_loop_should_end(Ptr<?> data, @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_napi_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_napi_init(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_napi_sqpoll_busy_poll(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_net_import_vec($arg1, $arg2, (const struct iovec *)$arg3, $arg4, $arg5)")
  public static int io_net_import_vec(Ptr<io_kiocb> req, Ptr<io_async_msghdr> iomsg,
      Ptr<iovec> uiov, @Unsigned int uvec_seg, int ddir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_net_kbuf_recyle(Ptr<io_kiocb> req, Ptr<io_async_msghdr> kmsg, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_netmsg_cache_free((const void *)$arg1)")
  public static void io_netmsg_cache_free(Ptr<?> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_netmsg_recycle(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_no_issue(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_nop_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_nop_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_notif_tw_complete(Ptr<io_kiocb> notif,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_open_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_openat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_openat2(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_openat2_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_openat2_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_openat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_openat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_mapped_region> io_pbuf_get_region(Ptr<io_ring_ctx> ctx, @Unsigned int bgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<page>> io_pin_pages(@Unsigned long uaddr, @Unsigned long len,
      Ptr<java.lang.Integer> npages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_pipe_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_pipe_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_add(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_poll_add_hash(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_poll_add_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_poll_add_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_poll_can_finish_inline(Ptr<io_kiocb> req, Ptr<io_poll_table> pt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_cancel(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_check_events(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_poll_execute(Ptr<io_kiocb> req, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_kiocb> io_poll_find(Ptr<io_ring_ctx> ctx, boolean poll_only,
      Ptr<io_cancel_data> cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_issue(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_poll_queue_proc(Ptr<file> file, Ptr<wait_queue_head> head,
      Ptr<poll_table_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_remove(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_poll_remove_all(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_poll_remove_entries(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_poll_remove_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_poll_remove_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_poll_task_func(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_poll_wake(Ptr<wait_queue_entry> wait, @Unsigned int mode, int sync,
      Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_post_aux_cqe(Ptr<io_ring_ctx> ctx, @Unsigned long user_data, int res,
      @Unsigned int cflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_pp_nl_fill(Ptr<?> mp_priv, Ptr<sk_buff> rsp, Ptr<netdev_rx_queue> rxq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_pp_uninstall(Ptr<?> mp_priv, Ptr<netdev_rx_queue> rxq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("netmem_ref") long io_pp_zc_alloc_netmems(Ptr<page_pool> pp,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_pp_zc_destroy(Ptr<page_pool> pp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_pp_zc_init(Ptr<page_pool> pp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_pp_zc_release_netmem(Ptr<page_pool> pp,
      @Unsigned @OriginalName("netmem_ref") long netmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_prep_async_link(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_prep_async_work(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_read($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_read(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_read_fixed($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_read_fixed(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_readv($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_readv(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_readv_fixed($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_readv_fixed(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_reg_iovec($arg1, $arg2, (const struct iovec *)$arg3, $arg4)")
  public static int io_prep_reg_iovec(Ptr<io_kiocb> req, Ptr<iou_vec> iv, Ptr<iovec> uvec,
      @Unsigned long uvec_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_rw($arg1, (const struct io_uring_sqe *)$arg2, $arg3)")
  public static int io_prep_rw(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe, int ddir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_write($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_write(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_write_fixed($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_write_fixed(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_writev($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_writev(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_prep_writev_fixed($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_prep_writev_fixed(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_provide_buffers_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_provide_buffers_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> io_provided_buffer_select(Ptr<io_kiocb> req,
      Ptr<java.lang. @Unsigned Long> len, Ptr<io_buffer_list> bl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_put_bl(Ptr<io_ring_ctx> ctx, Ptr<io_buffer_list> bl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_put_rsrc_node(Ptr<io_ring_ctx> ctx, Ptr<io_rsrc_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_put_sq_data(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_async(Ptr<io_kiocb> req, @Unsigned int issue_flags, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_deferred(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_iowq(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_linked_timeout(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_next(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_queue_sqe_fallback(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_queue_worker_create(Ptr<io_worker> worker, Ptr<io_wq_acct> acct,
      @OriginalName("task_work_func_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_read(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_read_fixed(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_read_mshot(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_read_mshot_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_read_mshot_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_readv_writev_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_recv(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_recv_buf_select(Ptr<io_kiocb> req, Ptr<io_async_msghdr> kmsg,
      Ptr<java.lang. @Unsigned Long> len, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_recv_finish(Ptr<io_kiocb> req, Ptr<java.lang.Integer> ret,
      Ptr<io_async_msghdr> kmsg, boolean mshot_finished, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_recvmsg(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_recvmsg_multishot(Ptr<socket> sock, Ptr<io_sr_msg> io,
      Ptr<io_async_msghdr> kmsg, @Unsigned int flags,
      Ptr<java.lang. @OriginalName("bool") Boolean> finished) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_recvmsg_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_recvmsg_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_recvzc_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_recvzc_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_clone_buffers(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_file_alloc_range(Ptr<io_ring_ctx> ctx,
      Ptr<io_uring_file_index_range> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_files_update(Ptr<io_ring_ctx> ctx, Ptr<?> arg,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_iowq_aff(Ptr<io_ring_ctx> ctx, Ptr<?> arg, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_iowq_max_workers(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_mem_region(Ptr<io_ring_ctx> ctx, Ptr<?> uarg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_napi(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_pbuf_ring(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_pbuf_status(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_resize_rings(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_restrictions(Ptr<io_ring_ctx> ctx, Ptr<?> arg,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_rsrc(Ptr<io_ring_ctx> ctx, Ptr<?> arg, @Unsigned int size,
      @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_rsrc_update(Ptr<io_ring_ctx> ctx, Ptr<?> arg, @Unsigned int size,
      @Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_register_zcrx_ifq(Ptr<io_ring_ctx> ctx, Ptr<io_uring_zcrx_ifq_reg> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_release_dmabuf(Ptr<io_zcrx_mem> mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_release_ubuf(Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_remove_buffers_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_remove_buffers_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_renameat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_renameat_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_renameat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_renameat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_caches_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_complete_post(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_defer_failed(Ptr<io_kiocb> req, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_end_write(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_io_end(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_req_post_cqe(Ptr<io_kiocb> req, int res, @Unsigned int cflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_req_post_cqe32(Ptr<io_kiocb> req, Ptr<io_uring_cqe> cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_queue_iowq(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_queue_iowq_tw(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_rw_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_cancel(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_link_timeout(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_queue(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_queue_fail(Ptr<io_kiocb> req, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_submit(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_task_work_add_remote(Ptr<io_kiocb> req, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_track_inflight(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_tw_fail_links(Ptr<io_kiocb> link,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_req_uring_cleanup(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_ring_add_registered_file(Ptr<io_uring_task> tctx, Ptr<file> file, int start,
      int end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_ring_buffers_peek(Ptr<io_kiocb> req, Ptr<buf_sel_arg> arg,
      Ptr<io_buffer_list> bl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_ring_ctx> io_ring_ctx_alloc(Ptr<io_uring_params> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_ring_ctx_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_ring_ctx_ref_free(Ptr<percpu_ref> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_ring_ctx_wait_and_kill(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_ring_exit_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_ringfd_register(Ptr<io_ring_ctx> ctx, Ptr<?> __arg, @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_ringfd_unregister(Ptr<io_ring_ctx> ctx, Ptr<?> __arg,
      @Unsigned int nr_args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_rings_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_rsrc_cache_free(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_rsrc_cache_init(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_rsrc_data_alloc(Ptr<io_rsrc_data> data, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_rsrc_data_free(Ptr<io_ring_ctx> ctx, Ptr<io_rsrc_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_rsrc_node> io_rsrc_node_alloc(Ptr<io_ring_ctx> ctx, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_run_local_work(Ptr<io_ring_ctx> ctx, int min_events, int max_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_run_task_work() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_run_task_work_sig(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_rw_alloc_async(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_rw_cache_free((const void *)$arg1)")
  public static void io_rw_cache_free(Ptr<?> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_rw_fail(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_rw_init_file(Ptr<io_kiocb> req, @Unsigned @OriginalName("fmode_t") int mode,
      int rw_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_rw_recycle(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_rw_should_reissue(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_schedule() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_schedule_finish(int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_schedule_prepare() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long io_schedule_timeout(long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_send(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_send_setup($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_send_setup(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_send_zc(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_send_zc_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_send_zc_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_send_zc_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sendmsg(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_sendmsg_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_sendmsg_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sendmsg_recvmsg_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_sendmsg_setup($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_sendmsg_setup(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sendmsg_zc(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sendrecv_fail(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_setxattr(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_setxattr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_setxattr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_sfr_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_sfr_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sg_from_iter(Ptr<sk_buff> skb, Ptr<iov_iter> from, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sg_from_iter_iovec(Ptr<sk_buff> skb, Ptr<iov_iter> from,
      @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_shutdown_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_shutdown_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_shutdown_zcrx_ifqs(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_socket_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_socket_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_splice_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> io_splice_get_file(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_splice_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_splice_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long io_sq_cpu_usec(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sq_offload_create(Ptr<io_ring_ctx> ctx, Ptr<io_uring_params> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sq_thread(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sq_thread_finish(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sq_thread_park(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sq_thread_stop(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sq_thread_unpark(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int io_sq_tw(Ptr<Ptr<llist_node>> retry_list, int max_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_sqd_handle_event(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sqd_update_thread_idle(Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_rsrc_node> io_sqe_buffer_register(Ptr<io_ring_ctx> ctx, Ptr<iovec> iov,
      Ptr<Ptr<page>> last_hpage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sqe_buffers_register(Ptr<io_ring_ctx> ctx, Ptr<?> arg, @Unsigned int nr_args,
      Ptr<java.lang. @Unsigned Long> tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sqe_buffers_unregister(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sqe_files_register(Ptr<io_ring_ctx> ctx, Ptr<?> arg, @Unsigned int nr_args,
      Ptr<java.lang. @Unsigned Long> tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sqe_files_unregister(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_sqpoll_wait_sq(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sqpoll_wq_cpu_affinity(Ptr<io_ring_ctx> ctx,
      @OriginalName("cpumask_var_t") Ptr<cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_statx_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_statx_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_statx_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_submit_fail_init((const struct io_uring_sqe *)$arg1, $arg2, $arg3)")
  public static int io_submit_fail_init(Ptr<io_uring_sqe> sqe, Ptr<io_kiocb> req, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_submit_flush_completions(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_submit_one(Ptr<kioctx> ctx, Ptr<iocb> user_iocb, boolean compat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_submit_sqes(Ptr<io_ring_ctx> ctx, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_symlinkat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_symlinkat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_symlinkat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sync_cancel(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_sync_file_range(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_task_refs_refill(Ptr<io_uring_task> tctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_task_work_match(Ptr<callback_head> cb, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_task_worker_match(Ptr<callback_head> cb, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_tctx_exit_cb(Ptr<callback_head> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_tee(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_tee_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_tee_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_timeout_cancel(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_timeout_complete(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_kiocb> io_timeout_extract(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart io_timeout_fn(Ptr<hrtimer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_timeout_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_timeout_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_timeout_remove(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_timeout_remove_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_timeout_remove_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_tlb_hiwater_get(Ptr<?> data, Ptr<java.lang. @Unsigned Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_tlb_hiwater_set(Ptr<?> data, @Unsigned long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_tlb_transient_used_get(Ptr<?> data, Ptr<java.lang. @Unsigned Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_tlb_used_get(Ptr<?> data, Ptr<java.lang. @Unsigned Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_try_cancel(Ptr<io_uring_task> tctx, Ptr<io_cancel_data> cd,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_tx_ubuf_complete(Ptr<sk_buff> skb, Ptr<ubuf_info> uarg, boolean success) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long io_type_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_unaccount_mem(Ptr<io_ring_ctx> ctx, @Unsigned long nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_unlinkat(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_unlinkat_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_unlinkat_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_unlinkat_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_unregister_napi(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_unregister_pbuf_ring(Ptr<io_ring_ctx> ctx, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_unregister_personality(Ptr<io_ring_ctx> ctx, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_unregister_zcrx_ifqs(Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> io_uring_alloc_async_data(Ptr<io_alloc_cache> cache, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_alloc_task_context(Ptr<task_struct> task, Ptr<io_ring_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cancel_generic(boolean cancel_all, Ptr<io_sq_data> sqd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_classic_poll(Ptr<io_kiocb> req, Ptr<io_comp_batch> iob,
      @Unsigned int poll_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_clean_tctx(Ptr<io_uring_task> tctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_done(Ptr<io_uring_cmd> ioucmd, @OriginalName("ssize_t") long ret,
      @Unsigned long res2, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_cmd_import_fixed(@Unsigned long ubuf, @Unsigned long len, int rw,
      Ptr<iov_iter> iter, Ptr<io_uring_cmd> ioucmd, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_uring_cmd_import_fixed_vec($arg1, (const struct iovec *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int io_uring_cmd_import_fixed_vec(Ptr<io_uring_cmd> ioucmd, Ptr<iovec> uvec,
      @Unsigned long uvec_segs, int ddir, Ptr<iov_iter> iter, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_issue_blocking(Ptr<io_uring_cmd> ioucmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_mark_cancelable(Ptr<io_uring_cmd> cmd,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_uring_cmd_post_mshot_cqe32(Ptr<io_uring_cmd> cmd,
      @Unsigned int issue_flags, Ptr<io_uring_cqe> cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_uring_cmd_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_uring_cmd_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_cmd_sock(Ptr<io_uring_cmd> cmd, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_sqe_copy(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_cmd_work(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_create(@Unsigned int entries, Ptr<io_uring_params> p,
      Ptr<io_uring_params> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_del_tctx_node(@Unsigned long index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_drop_tctx_refs(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_fill_params(@Unsigned int entries, Ptr<io_uring_params> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)io_uring_get_opcode($arg1))")
  public static String io_uring_get_opcode(char opcode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long io_uring_get_unmapped_area(Ptr<file> filp, @Unsigned long addr,
      @Unsigned long len, @Unsigned long pgoff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_uring_op_supported(char opcode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_optable_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int io_uring_poll(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> io_uring_register_get_file(@Unsigned int fd, boolean registered) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long io_uring_setup(@Unsigned int entries, Ptr<io_uring_params> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_show_fdinfo(Ptr<seq_file> m, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_uring_sync_msg_ring(Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_uring_try_cancel_requests(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all, boolean is_sqpoll_thread) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_uring_try_cancel_uring_cmd(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_uring_unreg_ringfd() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_validate_user_buf_range(@Unsigned long uaddr, @Unsigned long ulen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_vec_free(Ptr<iou_vec> iv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_vec_realloc(Ptr<iou_vec> iv, @Unsigned int nr_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_waitid_cancel(Ptr<io_ring_ctx> ctx, Ptr<io_cancel_data> cd,
      @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_waitid_cb(Ptr<io_kiocb> req,
      @OriginalName("io_tw_token_t") io_tw_state tw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_waitid_complete(Ptr<io_kiocb> req, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_waitid_copy_si(Ptr<io_kiocb> req, int signo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("io_waitid_prep($arg1, (const struct io_uring_sqe *)$arg2)")
  public static int io_waitid_prep(Ptr<io_kiocb> req, Ptr<io_uring_sqe> sqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_waitid_remove_all(Ptr<io_ring_ctx> ctx, Ptr<io_uring_task> tctx,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_waitid_wait(Ptr<wait_queue_entry> wait, @Unsigned int mode, int sync,
      Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wake_function(Ptr<wait_queue_entry> curr, @Unsigned int mode, int wake_flags,
      Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_watchdog_func(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_worker_cancel_cb(Ptr<io_worker> worker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_worker_handle_work(Ptr<io_wq_acct> acct, Ptr<io_worker> worker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_worker_release(Ptr<io_worker> worker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_workqueue_create(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static io_wq_cancel io_wq_cancel_cb(Ptr<io_wq> wq, Ptr<?> cancel, Ptr<?> data,
      boolean cancel_all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_cpu_affinity(Ptr<io_uring_task> tctx,
      @OriginalName("cpumask_var_t") Ptr<cpumask> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_cpu_offline(@Unsigned int cpu, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_cpu_online(@Unsigned int cpu, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_wq> io_wq_create(@Unsigned int bounded, Ptr<io_wq_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_dec_running(Ptr<io_worker> worker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_enqueue(Ptr<io_wq> wq, Ptr<io_wq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_exit_start(Ptr<io_wq> wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_wq_work> io_wq_free_work(Ptr<io_wq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_hash_wake(Ptr<wait_queue_entry> wait, @Unsigned int mode, int sync,
      Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_hash_work(Ptr<io_wq_work> work, Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_max_workers(Ptr<io_wq> wq, Ptr<java.lang.Integer> new_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_put_and_exit(Ptr<io_wq> wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_submit_work(Ptr<io_wq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_work_match_all(Ptr<io_wq_work> work, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_work_match_item(Ptr<io_wq_work> work, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_wq_worker(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_worker_affinity(Ptr<io_worker> worker, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_worker_cancel(Ptr<io_worker> worker, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_worker_running(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_wq_worker_sleeping(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_worker_stopped() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean io_wq_worker_wake(Ptr<io_worker> worker, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_write(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_write_fixed(Ptr<io_kiocb> req, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_xattr_cleanup(Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_zcrx_create_area(Ptr<io_zcrx_ifq> ifq, Ptr<Ptr<io_zcrx_area>> res,
      Ptr<io_uring_zcrx_area_reg> area_reg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_zcrx_free_area(Ptr<io_zcrx_area> area) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<io_mapped_region> io_zcrx_get_region(Ptr<io_ring_ctx> ctx, @Unsigned int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_zcrx_ifq_free(Ptr<io_zcrx_ifq> ifq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_zcrx_recv(Ptr<io_kiocb> req, Ptr<io_zcrx_ifq> ifq, Ptr<socket> sock,
      @Unsigned int flags, @Unsigned int issue_flags, Ptr<java.lang. @Unsigned Integer> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int io_zcrx_recv_skb(Ptr<read_descriptor_t> desc, Ptr<sk_buff> skb,
      @Unsigned int offset, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_zcrx_return_niov(Ptr<net_iov> niov) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_zcrx_ring_refill(Ptr<page_pool> pp, Ptr<io_zcrx_ifq> ifq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void io_zcrx_unmap_area(Ptr<io_zcrx_ifq> ifq, Ptr<io_zcrx_area> area) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_context extends Struct {
    public @OriginalName("atomic_long_t") atomic64_t refcount;

    public atomic_t active_ref;

    public @Unsigned short ioprio;

    public @OriginalName("spinlock_t") spinlock lock;

    public xarray icq_tree;

    public Ptr<io_cq> icq_hint;

    public hlist_head icq_list;

    public work_struct release_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cq extends Struct {
    public Ptr<request_queue> q;

    public Ptr<io_context> ioc;

    @InlineUnion(1072)
    public list_head q_node;

    @InlineUnion(1072)
    public Ptr<kmem_cache> __rcu_icq_cache;

    @InlineUnion(1073)
    public hlist_node ioc_node;

    @InlineUnion(1073)
    public callback_head __rcu_head;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_comp_batch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_comp_batch extends Struct {
    public rq_list req_list;

    public boolean need_ts;

    public Ptr<?> complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_bitmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_bitmap extends Struct {
    public @Unsigned long sequence;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int max;

    public @Unsigned long @Size(1024) [] bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 direction; u8 size; short unsigned int port; unsigned int count; long long unsigned int data_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_of_anon_member_of_kvm_run extends Struct {
    public char direction;

    public char size;

    public @Unsigned short port;

    public @Unsigned int count;

    public @Unsigned long data_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tlb_mem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tlb_mem extends Struct {
    public io_tlb_pool defpool;

    public @Unsigned long nslabs;

    public Ptr<dentry> debugfs;

    public boolean force_bounce;

    public boolean for_alloc;

    public boolean can_grow;

    public @Unsigned long phys_limit;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head pools;

    public work_struct dyn_alloc;

    public @OriginalName("atomic_long_t") atomic64_t total_used;

    public @OriginalName("atomic_long_t") atomic64_t used_hiwater;

    public @OriginalName("atomic_long_t") atomic64_t transient_nslabs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tlb_pool"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tlb_pool extends Struct {
    public @Unsigned @OriginalName("phys_addr_t") long start;

    public @Unsigned @OriginalName("phys_addr_t") long end;

    public Ptr<?> vaddr;

    public @Unsigned long nslabs;

    public boolean late_alloc;

    public @Unsigned int nareas;

    public @Unsigned int area_nslabs;

    public Ptr<io_tlb_area> areas;

    public Ptr<io_tlb_slot> slots;

    public list_head node;

    public callback_head rcu;

    public boolean _transient;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_apic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_apic extends Struct {
    public @Unsigned int index;

    public @Unsigned int @Size(3) [] unused;

    public @Unsigned int data;

    public @Unsigned int @Size(11) [] unused2;

    public @Unsigned int eoi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_task extends Struct {
    public int cached_refs;

    public Ptr<io_ring_ctx> last;

    public Ptr<task_struct> task;

    public Ptr<io_wq> io_wq;

    public Ptr<file> @Size(16) [] registered_rings;

    public xarray xa;

    public wait_queue_head wait;

    public atomic_t in_cancel;

    public atomic_t inflight_tracked;

    public percpu_counter inflight;

    public anon_member_of_io_uring_task anon10;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_sqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_sqe extends Struct {
    public char opcode;

    public char flags;

    public @Unsigned short ioprio;

    public int fd;

    @InlineUnion(11382)
    public @Unsigned long off;

    @InlineUnion(11382)
    public @Unsigned long addr2;

    @InlineUnion(11382)
    public anon_member_of_anon_member_of_io_uring_sqe anon4$2;

    @InlineUnion(11384)
    public @Unsigned long addr;

    @InlineUnion(11384)
    public @Unsigned long splice_off_in;

    @InlineUnion(11384)
    public anon_member_of_anon_member_of_io_uring_sqe anon5$2;

    public @Unsigned int len;

    @InlineUnion(11385)
    public @Unsigned int rw_flags;

    @InlineUnion(11385)
    public @Unsigned int fsync_flags;

    @InlineUnion(11385)
    public @Unsigned short poll_events;

    @InlineUnion(11385)
    public @Unsigned int poll32_events;

    @InlineUnion(11385)
    public @Unsigned int sync_range_flags;

    @InlineUnion(11385)
    public @Unsigned int msg_flags;

    @InlineUnion(11385)
    public @Unsigned int timeout_flags;

    @InlineUnion(11385)
    public @Unsigned int accept_flags;

    @InlineUnion(11385)
    public @Unsigned int cancel_flags;

    @InlineUnion(11385)
    public @Unsigned int open_flags;

    @InlineUnion(11385)
    public @Unsigned int statx_flags;

    @InlineUnion(11385)
    public @Unsigned int fadvise_advice;

    @InlineUnion(11385)
    public @Unsigned int splice_flags;

    @InlineUnion(11385)
    public @Unsigned int rename_flags;

    @InlineUnion(11385)
    public @Unsigned int unlink_flags;

    @InlineUnion(11385)
    public @Unsigned int hardlink_flags;

    @InlineUnion(11385)
    public @Unsigned int xattr_flags;

    @InlineUnion(11385)
    public @Unsigned int msg_ring_flags;

    @InlineUnion(11385)
    public @Unsigned int uring_cmd_flags;

    @InlineUnion(11385)
    public @Unsigned int waitid_flags;

    @InlineUnion(11385)
    public @Unsigned int futex_flags;

    @InlineUnion(11385)
    public @Unsigned int install_fd_flags;

    @InlineUnion(11385)
    public @Unsigned int nop_flags;

    @InlineUnion(11385)
    public @Unsigned int pipe_flags;

    public @Unsigned long user_data;

    @InlineUnion(11386)
    public @Unsigned short buf_index;

    @InlineUnion(11386)
    public @Unsigned short buf_group;

    public @Unsigned short personality;

    @InlineUnion(11389)
    public int splice_fd_in;

    @InlineUnion(11389)
    public @Unsigned int file_index;

    @InlineUnion(11389)
    public @Unsigned int zcrx_ifq_idx;

    @InlineUnion(11389)
    public @Unsigned int optlen;

    @InlineUnion(11389)
    public anon_member_of_anon_member_of_io_uring_sqe anon11$4;

    @InlineUnion(11389)
    public anon_member_of_anon_member_of_io_uring_sqe anon11$5;

    @InlineUnion(11392)
    public anon_member_of_anon_member_of_io_uring_sqe anon12$0;

    @InlineUnion(11392)
    public anon_member_of_anon_member_of_io_uring_sqe anon12$1;

    @InlineUnion(11392)
    public @Unsigned long optval;

    @InlineUnion(11392)
    public char @Size(0) [] cmd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_sqe_flags_bit"
  )
  public enum io_uring_sqe_flags_bit implements Enum<io_uring_sqe_flags_bit>, TypedEnum<io_uring_sqe_flags_bit, java.lang. @Unsigned Integer> {
    /**
     * {@code IOSQE_FIXED_FILE_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IOSQE_FIXED_FILE_BIT"
    )
    IOSQE_FIXED_FILE_BIT,

    /**
     * {@code IOSQE_IO_DRAIN_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOSQE_IO_DRAIN_BIT"
    )
    IOSQE_IO_DRAIN_BIT,

    /**
     * {@code IOSQE_IO_LINK_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOSQE_IO_LINK_BIT"
    )
    IOSQE_IO_LINK_BIT,

    /**
     * {@code IOSQE_IO_HARDLINK_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IOSQE_IO_HARDLINK_BIT"
    )
    IOSQE_IO_HARDLINK_BIT,

    /**
     * {@code IOSQE_ASYNC_BIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IOSQE_ASYNC_BIT"
    )
    IOSQE_ASYNC_BIT,

    /**
     * {@code IOSQE_BUFFER_SELECT_BIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IOSQE_BUFFER_SELECT_BIT"
    )
    IOSQE_BUFFER_SELECT_BIT,

    /**
     * {@code IOSQE_CQE_SKIP_SUCCESS_BIT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IOSQE_CQE_SKIP_SUCCESS_BIT"
    )
    IOSQE_CQE_SKIP_SUCCESS_BIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_op"
  )
  public enum io_uring_op implements Enum<io_uring_op>, TypedEnum<io_uring_op, java.lang. @Unsigned Integer> {
    /**
     * {@code IORING_OP_NOP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IORING_OP_NOP"
    )
    IORING_OP_NOP,

    /**
     * {@code IORING_OP_READV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IORING_OP_READV"
    )
    IORING_OP_READV,

    /**
     * {@code IORING_OP_WRITEV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IORING_OP_WRITEV"
    )
    IORING_OP_WRITEV,

    /**
     * {@code IORING_OP_FSYNC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IORING_OP_FSYNC"
    )
    IORING_OP_FSYNC,

    /**
     * {@code IORING_OP_READ_FIXED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IORING_OP_READ_FIXED"
    )
    IORING_OP_READ_FIXED,

    /**
     * {@code IORING_OP_WRITE_FIXED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IORING_OP_WRITE_FIXED"
    )
    IORING_OP_WRITE_FIXED,

    /**
     * {@code IORING_OP_POLL_ADD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IORING_OP_POLL_ADD"
    )
    IORING_OP_POLL_ADD,

    /**
     * {@code IORING_OP_POLL_REMOVE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IORING_OP_POLL_REMOVE"
    )
    IORING_OP_POLL_REMOVE,

    /**
     * {@code IORING_OP_SYNC_FILE_RANGE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IORING_OP_SYNC_FILE_RANGE"
    )
    IORING_OP_SYNC_FILE_RANGE,

    /**
     * {@code IORING_OP_SENDMSG = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IORING_OP_SENDMSG"
    )
    IORING_OP_SENDMSG,

    /**
     * {@code IORING_OP_RECVMSG = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IORING_OP_RECVMSG"
    )
    IORING_OP_RECVMSG,

    /**
     * {@code IORING_OP_TIMEOUT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IORING_OP_TIMEOUT"
    )
    IORING_OP_TIMEOUT,

    /**
     * {@code IORING_OP_TIMEOUT_REMOVE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IORING_OP_TIMEOUT_REMOVE"
    )
    IORING_OP_TIMEOUT_REMOVE,

    /**
     * {@code IORING_OP_ACCEPT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IORING_OP_ACCEPT"
    )
    IORING_OP_ACCEPT,

    /**
     * {@code IORING_OP_ASYNC_CANCEL = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IORING_OP_ASYNC_CANCEL"
    )
    IORING_OP_ASYNC_CANCEL,

    /**
     * {@code IORING_OP_LINK_TIMEOUT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IORING_OP_LINK_TIMEOUT"
    )
    IORING_OP_LINK_TIMEOUT,

    /**
     * {@code IORING_OP_CONNECT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IORING_OP_CONNECT"
    )
    IORING_OP_CONNECT,

    /**
     * {@code IORING_OP_FALLOCATE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IORING_OP_FALLOCATE"
    )
    IORING_OP_FALLOCATE,

    /**
     * {@code IORING_OP_OPENAT = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IORING_OP_OPENAT"
    )
    IORING_OP_OPENAT,

    /**
     * {@code IORING_OP_CLOSE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IORING_OP_CLOSE"
    )
    IORING_OP_CLOSE,

    /**
     * {@code IORING_OP_FILES_UPDATE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "IORING_OP_FILES_UPDATE"
    )
    IORING_OP_FILES_UPDATE,

    /**
     * {@code IORING_OP_STATX = 21}
     */
    @EnumMember(
        value = 21L,
        name = "IORING_OP_STATX"
    )
    IORING_OP_STATX,

    /**
     * {@code IORING_OP_READ = 22}
     */
    @EnumMember(
        value = 22L,
        name = "IORING_OP_READ"
    )
    IORING_OP_READ,

    /**
     * {@code IORING_OP_WRITE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "IORING_OP_WRITE"
    )
    IORING_OP_WRITE,

    /**
     * {@code IORING_OP_FADVISE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "IORING_OP_FADVISE"
    )
    IORING_OP_FADVISE,

    /**
     * {@code IORING_OP_MADVISE = 25}
     */
    @EnumMember(
        value = 25L,
        name = "IORING_OP_MADVISE"
    )
    IORING_OP_MADVISE,

    /**
     * {@code IORING_OP_SEND = 26}
     */
    @EnumMember(
        value = 26L,
        name = "IORING_OP_SEND"
    )
    IORING_OP_SEND,

    /**
     * {@code IORING_OP_RECV = 27}
     */
    @EnumMember(
        value = 27L,
        name = "IORING_OP_RECV"
    )
    IORING_OP_RECV,

    /**
     * {@code IORING_OP_OPENAT2 = 28}
     */
    @EnumMember(
        value = 28L,
        name = "IORING_OP_OPENAT2"
    )
    IORING_OP_OPENAT2,

    /**
     * {@code IORING_OP_EPOLL_CTL = 29}
     */
    @EnumMember(
        value = 29L,
        name = "IORING_OP_EPOLL_CTL"
    )
    IORING_OP_EPOLL_CTL,

    /**
     * {@code IORING_OP_SPLICE = 30}
     */
    @EnumMember(
        value = 30L,
        name = "IORING_OP_SPLICE"
    )
    IORING_OP_SPLICE,

    /**
     * {@code IORING_OP_PROVIDE_BUFFERS = 31}
     */
    @EnumMember(
        value = 31L,
        name = "IORING_OP_PROVIDE_BUFFERS"
    )
    IORING_OP_PROVIDE_BUFFERS,

    /**
     * {@code IORING_OP_REMOVE_BUFFERS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IORING_OP_REMOVE_BUFFERS"
    )
    IORING_OP_REMOVE_BUFFERS,

    /**
     * {@code IORING_OP_TEE = 33}
     */
    @EnumMember(
        value = 33L,
        name = "IORING_OP_TEE"
    )
    IORING_OP_TEE,

    /**
     * {@code IORING_OP_SHUTDOWN = 34}
     */
    @EnumMember(
        value = 34L,
        name = "IORING_OP_SHUTDOWN"
    )
    IORING_OP_SHUTDOWN,

    /**
     * {@code IORING_OP_RENAMEAT = 35}
     */
    @EnumMember(
        value = 35L,
        name = "IORING_OP_RENAMEAT"
    )
    IORING_OP_RENAMEAT,

    /**
     * {@code IORING_OP_UNLINKAT = 36}
     */
    @EnumMember(
        value = 36L,
        name = "IORING_OP_UNLINKAT"
    )
    IORING_OP_UNLINKAT,

    /**
     * {@code IORING_OP_MKDIRAT = 37}
     */
    @EnumMember(
        value = 37L,
        name = "IORING_OP_MKDIRAT"
    )
    IORING_OP_MKDIRAT,

    /**
     * {@code IORING_OP_SYMLINKAT = 38}
     */
    @EnumMember(
        value = 38L,
        name = "IORING_OP_SYMLINKAT"
    )
    IORING_OP_SYMLINKAT,

    /**
     * {@code IORING_OP_LINKAT = 39}
     */
    @EnumMember(
        value = 39L,
        name = "IORING_OP_LINKAT"
    )
    IORING_OP_LINKAT,

    /**
     * {@code IORING_OP_MSG_RING = 40}
     */
    @EnumMember(
        value = 40L,
        name = "IORING_OP_MSG_RING"
    )
    IORING_OP_MSG_RING,

    /**
     * {@code IORING_OP_FSETXATTR = 41}
     */
    @EnumMember(
        value = 41L,
        name = "IORING_OP_FSETXATTR"
    )
    IORING_OP_FSETXATTR,

    /**
     * {@code IORING_OP_SETXATTR = 42}
     */
    @EnumMember(
        value = 42L,
        name = "IORING_OP_SETXATTR"
    )
    IORING_OP_SETXATTR,

    /**
     * {@code IORING_OP_FGETXATTR = 43}
     */
    @EnumMember(
        value = 43L,
        name = "IORING_OP_FGETXATTR"
    )
    IORING_OP_FGETXATTR,

    /**
     * {@code IORING_OP_GETXATTR = 44}
     */
    @EnumMember(
        value = 44L,
        name = "IORING_OP_GETXATTR"
    )
    IORING_OP_GETXATTR,

    /**
     * {@code IORING_OP_SOCKET = 45}
     */
    @EnumMember(
        value = 45L,
        name = "IORING_OP_SOCKET"
    )
    IORING_OP_SOCKET,

    /**
     * {@code IORING_OP_URING_CMD = 46}
     */
    @EnumMember(
        value = 46L,
        name = "IORING_OP_URING_CMD"
    )
    IORING_OP_URING_CMD,

    /**
     * {@code IORING_OP_SEND_ZC = 47}
     */
    @EnumMember(
        value = 47L,
        name = "IORING_OP_SEND_ZC"
    )
    IORING_OP_SEND_ZC,

    /**
     * {@code IORING_OP_SENDMSG_ZC = 48}
     */
    @EnumMember(
        value = 48L,
        name = "IORING_OP_SENDMSG_ZC"
    )
    IORING_OP_SENDMSG_ZC,

    /**
     * {@code IORING_OP_READ_MULTISHOT = 49}
     */
    @EnumMember(
        value = 49L,
        name = "IORING_OP_READ_MULTISHOT"
    )
    IORING_OP_READ_MULTISHOT,

    /**
     * {@code IORING_OP_WAITID = 50}
     */
    @EnumMember(
        value = 50L,
        name = "IORING_OP_WAITID"
    )
    IORING_OP_WAITID,

    /**
     * {@code IORING_OP_FUTEX_WAIT = 51}
     */
    @EnumMember(
        value = 51L,
        name = "IORING_OP_FUTEX_WAIT"
    )
    IORING_OP_FUTEX_WAIT,

    /**
     * {@code IORING_OP_FUTEX_WAKE = 52}
     */
    @EnumMember(
        value = 52L,
        name = "IORING_OP_FUTEX_WAKE"
    )
    IORING_OP_FUTEX_WAKE,

    /**
     * {@code IORING_OP_FUTEX_WAITV = 53}
     */
    @EnumMember(
        value = 53L,
        name = "IORING_OP_FUTEX_WAITV"
    )
    IORING_OP_FUTEX_WAITV,

    /**
     * {@code IORING_OP_FIXED_FD_INSTALL = 54}
     */
    @EnumMember(
        value = 54L,
        name = "IORING_OP_FIXED_FD_INSTALL"
    )
    IORING_OP_FIXED_FD_INSTALL,

    /**
     * {@code IORING_OP_FTRUNCATE = 55}
     */
    @EnumMember(
        value = 55L,
        name = "IORING_OP_FTRUNCATE"
    )
    IORING_OP_FTRUNCATE,

    /**
     * {@code IORING_OP_BIND = 56}
     */
    @EnumMember(
        value = 56L,
        name = "IORING_OP_BIND"
    )
    IORING_OP_BIND,

    /**
     * {@code IORING_OP_LISTEN = 57}
     */
    @EnumMember(
        value = 57L,
        name = "IORING_OP_LISTEN"
    )
    IORING_OP_LISTEN,

    /**
     * {@code IORING_OP_RECV_ZC = 58}
     */
    @EnumMember(
        value = 58L,
        name = "IORING_OP_RECV_ZC"
    )
    IORING_OP_RECV_ZC,

    /**
     * {@code IORING_OP_EPOLL_WAIT = 59}
     */
    @EnumMember(
        value = 59L,
        name = "IORING_OP_EPOLL_WAIT"
    )
    IORING_OP_EPOLL_WAIT,

    /**
     * {@code IORING_OP_READV_FIXED = 60}
     */
    @EnumMember(
        value = 60L,
        name = "IORING_OP_READV_FIXED"
    )
    IORING_OP_READV_FIXED,

    /**
     * {@code IORING_OP_WRITEV_FIXED = 61}
     */
    @EnumMember(
        value = 61L,
        name = "IORING_OP_WRITEV_FIXED"
    )
    IORING_OP_WRITEV_FIXED,

    /**
     * {@code IORING_OP_PIPE = 62}
     */
    @EnumMember(
        value = 62L,
        name = "IORING_OP_PIPE"
    )
    IORING_OP_PIPE,

    /**
     * {@code IORING_OP_LAST = 63}
     */
    @EnumMember(
        value = 63L,
        name = "IORING_OP_LAST"
    )
    IORING_OP_LAST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_cqe extends Struct {
    public @Unsigned long user_data;

    public int res;

    public @Unsigned int flags;

    public @Unsigned long @Size(0) [] big_cqe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_register_op"
  )
  public enum io_uring_register_op implements Enum<io_uring_register_op>, TypedEnum<io_uring_register_op, java.lang. @Unsigned Integer> {
    /**
     * {@code IORING_REGISTER_BUFFERS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IORING_REGISTER_BUFFERS"
    )
    IORING_REGISTER_BUFFERS,

    /**
     * {@code IORING_UNREGISTER_BUFFERS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IORING_UNREGISTER_BUFFERS"
    )
    IORING_UNREGISTER_BUFFERS,

    /**
     * {@code IORING_REGISTER_FILES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IORING_REGISTER_FILES"
    )
    IORING_REGISTER_FILES,

    /**
     * {@code IORING_UNREGISTER_FILES = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IORING_UNREGISTER_FILES"
    )
    IORING_UNREGISTER_FILES,

    /**
     * {@code IORING_REGISTER_EVENTFD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IORING_REGISTER_EVENTFD"
    )
    IORING_REGISTER_EVENTFD,

    /**
     * {@code IORING_UNREGISTER_EVENTFD = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IORING_UNREGISTER_EVENTFD"
    )
    IORING_UNREGISTER_EVENTFD,

    /**
     * {@code IORING_REGISTER_FILES_UPDATE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IORING_REGISTER_FILES_UPDATE"
    )
    IORING_REGISTER_FILES_UPDATE,

    /**
     * {@code IORING_REGISTER_EVENTFD_ASYNC = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IORING_REGISTER_EVENTFD_ASYNC"
    )
    IORING_REGISTER_EVENTFD_ASYNC,

    /**
     * {@code IORING_REGISTER_PROBE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IORING_REGISTER_PROBE"
    )
    IORING_REGISTER_PROBE,

    /**
     * {@code IORING_REGISTER_PERSONALITY = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IORING_REGISTER_PERSONALITY"
    )
    IORING_REGISTER_PERSONALITY,

    /**
     * {@code IORING_UNREGISTER_PERSONALITY = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IORING_UNREGISTER_PERSONALITY"
    )
    IORING_UNREGISTER_PERSONALITY,

    /**
     * {@code IORING_REGISTER_RESTRICTIONS = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IORING_REGISTER_RESTRICTIONS"
    )
    IORING_REGISTER_RESTRICTIONS,

    /**
     * {@code IORING_REGISTER_ENABLE_RINGS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IORING_REGISTER_ENABLE_RINGS"
    )
    IORING_REGISTER_ENABLE_RINGS,

    /**
     * {@code IORING_REGISTER_FILES2 = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IORING_REGISTER_FILES2"
    )
    IORING_REGISTER_FILES2,

    /**
     * {@code IORING_REGISTER_FILES_UPDATE2 = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IORING_REGISTER_FILES_UPDATE2"
    )
    IORING_REGISTER_FILES_UPDATE2,

    /**
     * {@code IORING_REGISTER_BUFFERS2 = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IORING_REGISTER_BUFFERS2"
    )
    IORING_REGISTER_BUFFERS2,

    /**
     * {@code IORING_REGISTER_BUFFERS_UPDATE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IORING_REGISTER_BUFFERS_UPDATE"
    )
    IORING_REGISTER_BUFFERS_UPDATE,

    /**
     * {@code IORING_REGISTER_IOWQ_AFF = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IORING_REGISTER_IOWQ_AFF"
    )
    IORING_REGISTER_IOWQ_AFF,

    /**
     * {@code IORING_UNREGISTER_IOWQ_AFF = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IORING_UNREGISTER_IOWQ_AFF"
    )
    IORING_UNREGISTER_IOWQ_AFF,

    /**
     * {@code IORING_REGISTER_IOWQ_MAX_WORKERS = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IORING_REGISTER_IOWQ_MAX_WORKERS"
    )
    IORING_REGISTER_IOWQ_MAX_WORKERS,

    /**
     * {@code IORING_REGISTER_RING_FDS = 20}
     */
    @EnumMember(
        value = 20L,
        name = "IORING_REGISTER_RING_FDS"
    )
    IORING_REGISTER_RING_FDS,

    /**
     * {@code IORING_UNREGISTER_RING_FDS = 21}
     */
    @EnumMember(
        value = 21L,
        name = "IORING_UNREGISTER_RING_FDS"
    )
    IORING_UNREGISTER_RING_FDS,

    /**
     * {@code IORING_REGISTER_PBUF_RING = 22}
     */
    @EnumMember(
        value = 22L,
        name = "IORING_REGISTER_PBUF_RING"
    )
    IORING_REGISTER_PBUF_RING,

    /**
     * {@code IORING_UNREGISTER_PBUF_RING = 23}
     */
    @EnumMember(
        value = 23L,
        name = "IORING_UNREGISTER_PBUF_RING"
    )
    IORING_UNREGISTER_PBUF_RING,

    /**
     * {@code IORING_REGISTER_SYNC_CANCEL = 24}
     */
    @EnumMember(
        value = 24L,
        name = "IORING_REGISTER_SYNC_CANCEL"
    )
    IORING_REGISTER_SYNC_CANCEL,

    /**
     * {@code IORING_REGISTER_FILE_ALLOC_RANGE = 25}
     */
    @EnumMember(
        value = 25L,
        name = "IORING_REGISTER_FILE_ALLOC_RANGE"
    )
    IORING_REGISTER_FILE_ALLOC_RANGE,

    /**
     * {@code IORING_REGISTER_PBUF_STATUS = 26}
     */
    @EnumMember(
        value = 26L,
        name = "IORING_REGISTER_PBUF_STATUS"
    )
    IORING_REGISTER_PBUF_STATUS,

    /**
     * {@code IORING_REGISTER_NAPI = 27}
     */
    @EnumMember(
        value = 27L,
        name = "IORING_REGISTER_NAPI"
    )
    IORING_REGISTER_NAPI,

    /**
     * {@code IORING_UNREGISTER_NAPI = 28}
     */
    @EnumMember(
        value = 28L,
        name = "IORING_UNREGISTER_NAPI"
    )
    IORING_UNREGISTER_NAPI,

    /**
     * {@code IORING_REGISTER_CLOCK = 29}
     */
    @EnumMember(
        value = 29L,
        name = "IORING_REGISTER_CLOCK"
    )
    IORING_REGISTER_CLOCK,

    /**
     * {@code IORING_REGISTER_CLONE_BUFFERS = 30}
     */
    @EnumMember(
        value = 30L,
        name = "IORING_REGISTER_CLONE_BUFFERS"
    )
    IORING_REGISTER_CLONE_BUFFERS,

    /**
     * {@code IORING_REGISTER_SEND_MSG_RING = 31}
     */
    @EnumMember(
        value = 31L,
        name = "IORING_REGISTER_SEND_MSG_RING"
    )
    IORING_REGISTER_SEND_MSG_RING,

    /**
     * {@code IORING_REGISTER_ZCRX_IFQ = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IORING_REGISTER_ZCRX_IFQ"
    )
    IORING_REGISTER_ZCRX_IFQ,

    /**
     * {@code IORING_REGISTER_RESIZE_RINGS = 33}
     */
    @EnumMember(
        value = 33L,
        name = "IORING_REGISTER_RESIZE_RINGS"
    )
    IORING_REGISTER_RESIZE_RINGS,

    /**
     * {@code IORING_REGISTER_MEM_REGION = 34}
     */
    @EnumMember(
        value = 34L,
        name = "IORING_REGISTER_MEM_REGION"
    )
    IORING_REGISTER_MEM_REGION,

    /**
     * {@code IORING_REGISTER_LAST = 35}
     */
    @EnumMember(
        value = 35L,
        name = "IORING_REGISTER_LAST"
    )
    IORING_REGISTER_LAST,

    /**
     * {@code IORING_REGISTER_USE_REGISTERED_RING = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "IORING_REGISTER_USE_REGISTERED_RING"
    )
    IORING_REGISTER_USE_REGISTERED_RING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_work_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_work_node extends Struct {
    public Ptr<io_wq_work_node> next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_work_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_work_list extends Struct {
    public Ptr<io_wq_work_node> first;

    public Ptr<io_wq_work_node> last;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_work extends Struct {
    public io_wq_work_node list;

    public atomic_t flags;

    public int cancel_seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rsrc_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rsrc_data extends Struct {
    public @Unsigned int nr;

    public Ptr<Ptr<io_rsrc_node>> nodes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_file_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_file_table extends Struct {
    public io_rsrc_data data;

    public Ptr<java.lang. @Unsigned Long> bitmap;

    public @Unsigned int alloc_hint;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_hash_bucket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_hash_bucket extends Struct {
    public hlist_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_hash_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_hash_table extends Struct {
    public Ptr<io_hash_bucket> hbs;

    public @Unsigned int hash_bits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_mapped_region"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_mapped_region extends Struct {
    public Ptr<Ptr<page>> pages;

    public Ptr<?> ptr;

    public @Unsigned int nr_pages;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_ring_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_ring_ctx extends Struct {
    public anon_member_of_io_ring_ctx anon0;

    public anon_member_of_io_ring_ctx anon1;

    public anon_member_of_io_ring_ctx anon2;

    public anon_member_of_io_ring_ctx anon3;

    public anon_member_of_io_ring_ctx anon4;

    public @OriginalName("spinlock_t") spinlock completion_lock;

    public list_head cq_overflow_list;

    public hlist_head waitid_list;

    public hlist_head futex_list;

    public io_alloc_cache futex_cache;

    public Ptr<cred> sq_creds;

    public Ptr<io_sq_data> sq_data;

    public wait_queue_head sqo_sq_wait;

    public list_head sqd_list;

    public @Unsigned int file_alloc_start;

    public @Unsigned int file_alloc_end;

    public wait_queue_head poll_wq;

    public io_restriction restrictions;

    public xarray zcrx_ctxs;

    public @Unsigned int pers_next;

    public xarray personalities;

    public Ptr<io_wq_hash> hash_map;

    public Ptr<user_struct> user;

    public Ptr<mm_struct> mm_account;

    public llist_head fallback_llist;

    public delayed_work fallback_work;

    public work_struct exit_work;

    public list_head tctx_list;

    public completion ref_comp;

    public @Unsigned int @Size(2) [] iowq_limits;

    public callback_head poll_wq_task_work;

    public list_head defer_list;

    public @Unsigned int nr_drained;

    public list_head napi_list;

    public @OriginalName("spinlock_t") spinlock napi_lock;

    public @OriginalName("ktime_t") long napi_busy_poll_dt;

    public boolean napi_prefer_busy_poll;

    public char napi_track_mode;

    public hlist_head @Size(16) [] napi_ht;

    public @Unsigned int evfd_last_cq_tail;

    public @Unsigned int nr_req_allocated;

    public mutex mmap_lock;

    public io_mapped_region sq_region;

    public io_mapped_region ring_region;

    public io_mapped_region param_region;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring extends Struct {
    public @Unsigned int head;

    public @Unsigned int tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rings extends Struct {
    public io_uring sq;

    public io_uring cq;

    public @Unsigned int sq_ring_mask;

    public @Unsigned int cq_ring_mask;

    public @Unsigned int sq_ring_entries;

    public @Unsigned int cq_ring_entries;

    public @Unsigned int sq_dropped;

    public atomic_t sq_flags;

    public @Unsigned int cq_flags;

    public @Unsigned int cq_overflow;

    public io_uring_cqe @Size(0) [] cqes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_restriction"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_restriction extends Struct {
    public @Unsigned long @Size(1) [] register_op;

    public @Unsigned long @Size(1) [] sqe_op;

    public char sqe_flags_allowed;

    public char sqe_flags_required;

    public boolean registered;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_submit_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_submit_link extends Struct {
    public Ptr<io_kiocb> head;

    public Ptr<io_kiocb> last;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_kiocb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_kiocb extends Struct {
    @InlineUnion(11448)
    public Ptr<file> file;

    @InlineUnion(11448)
    public io_cmd_data cmd;

    public char opcode;

    public char iopoll_completed;

    public @Unsigned short buf_index;

    public @Unsigned int nr_tw;

    public @Unsigned @OriginalName("io_req_flags_t") long flags;

    public io_cqe cqe;

    public Ptr<io_ring_ctx> ctx;

    public Ptr<io_uring_task> tctx;

    @InlineUnion(11449)
    public Ptr<io_buffer> kbuf;

    @InlineUnion(11449)
    public Ptr<io_buffer_list> buf_list;

    @InlineUnion(11449)
    public Ptr<io_rsrc_node> buf_node;

    @InlineUnion(11452)
    public io_wq_work_node comp_list;

    @InlineUnion(11452)
    public @Unsigned @OriginalName("__poll_t") int apoll_events;

    public Ptr<io_rsrc_node> file_node;

    public atomic_t refs;

    public boolean cancel_seq_set;

    public io_task_work io_task_work;

    @InlineUnion(11453)
    public hlist_node hash_node;

    @InlineUnion(11453)
    public @Unsigned long iopoll_start;

    @InlineUnion(11453)
    public callback_head callback_head;

    public Ptr<async_poll> apoll;

    public Ptr<?> async_data;

    public atomic_t poll_refs;

    public Ptr<io_kiocb> link;

    public Ptr<cred> creds;

    public io_wq_work work;

    public io_big_cqe big_cqe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_submit_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_submit_state extends Struct {
    public io_wq_work_node free_list;

    public io_wq_work_list compl_reqs;

    public io_submit_link link;

    public boolean plug_started;

    public boolean need_plug;

    public boolean cq_flush;

    public @Unsigned short submit_nr;

    public blk_plug plug;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_alloc_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_alloc_cache extends Struct {
    public Ptr<Ptr<?>> entries;

    public @Unsigned int nr_cached;

    public @Unsigned int max_cached;

    public @Unsigned int elem_size;

    public @Unsigned int init_clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_hash extends Struct {
    public @OriginalName("refcount_t") refcount_struct refs;

    public @Unsigned long map;

    public wait_queue_head wait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tw_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tw_state extends Struct {
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_task_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_task_work extends Struct {
    public llist_node node;

    public @OriginalName("io_req_tw_func_t") Ptr<?> func;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cqe extends Struct {
    public @Unsigned long user_data;

    public int res;

    @InlineUnion(11445)
    public @Unsigned int flags;

    @InlineUnion(11445)
    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cmd_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cmd_data extends Struct {
    public Ptr<file> file;

    public char @Size(56) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_big_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_big_cqe extends Struct {
    public @Unsigned long extra1;

    public @Unsigned long extra2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tlb_area"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tlb_area extends Struct {
    public @Unsigned long used;

    public @Unsigned int index;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tlb_slot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tlb_slot extends Struct {
    public @Unsigned @OriginalName("phys_addr_t") long orig_addr;

    public @Unsigned long alloc_size;

    public @Unsigned short list;

    public @Unsigned short pad_slots;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_event extends Struct {
    public @Unsigned long data;

    public @Unsigned long obj;

    public long res;

    public long res2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_cmd extends Struct {
    public Ptr<file> file;

    public Ptr<io_uring_sqe> sqe;

    public Ptr<?> task_work_cb;

    public @Unsigned int cmd_op;

    public @Unsigned int flags;

    public char @Size(32) [] pdu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_cmd_flags"
  )
  public enum io_uring_cmd_flags implements Enum<io_uring_cmd_flags>, TypedEnum<io_uring_cmd_flags, java.lang.Integer> {
    /**
     * {@code IO_URING_F_COMPLETE_DEFER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_URING_F_COMPLETE_DEFER"
    )
    IO_URING_F_COMPLETE_DEFER,

    /**
     * {@code IO_URING_F_UNLOCKED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IO_URING_F_UNLOCKED"
    )
    IO_URING_F_UNLOCKED,

    /**
     * {@code IO_URING_F_MULTISHOT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IO_URING_F_MULTISHOT"
    )
    IO_URING_F_MULTISHOT,

    /**
     * {@code IO_URING_F_IOWQ = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IO_URING_F_IOWQ"
    )
    IO_URING_F_IOWQ,

    /**
     * {@code IO_URING_F_INLINE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IO_URING_F_INLINE"
    )
    IO_URING_F_INLINE,

    /**
     * {@code IO_URING_F_NONBLOCK = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "IO_URING_F_NONBLOCK"
    )
    IO_URING_F_NONBLOCK,

    /**
     * {@code IO_URING_F_SQE128 = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IO_URING_F_SQE128"
    )
    IO_URING_F_SQE128,

    /**
     * {@code IO_URING_F_CQE32 = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IO_URING_F_CQE32"
    )
    IO_URING_F_CQE32,

    /**
     * {@code IO_URING_F_IOPOLL = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "IO_URING_F_IOPOLL"
    )
    IO_URING_F_IOPOLL,

    /**
     * {@code IO_URING_F_CANCEL = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IO_URING_F_CANCEL"
    )
    IO_URING_F_CANCEL,

    /**
     * {@code IO_URING_F_COMPAT = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IO_URING_F_COMPAT"
    )
    IO_URING_F_COMPAT,

    /**
     * {@code IO_URING_F_TASK_DEAD = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "IO_URING_F_TASK_DEAD"
    )
    IO_URING_F_TASK_DEAD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_stats_per_prio"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_stats_per_prio extends Struct {
    public @Unsigned @OriginalName("uint32_t") int inserted;

    public @Unsigned @OriginalName("uint32_t") int merged;

    public @Unsigned @OriginalName("uint32_t") int dispatched;

    public atomic_t completed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_sqring_offsets"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_sqring_offsets extends Struct {
    public @Unsigned int head;

    public @Unsigned int tail;

    public @Unsigned int ring_mask;

    public @Unsigned int ring_entries;

    public @Unsigned int flags;

    public @Unsigned int dropped;

    public @Unsigned int array;

    public @Unsigned int resv1;

    public @Unsigned long user_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cqring_offsets"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cqring_offsets extends Struct {
    public @Unsigned int head;

    public @Unsigned int tail;

    public @Unsigned int ring_mask;

    public @Unsigned int ring_entries;

    public @Unsigned int overflow;

    public @Unsigned int cqes;

    public @Unsigned int flags;

    public @Unsigned int resv1;

    public @Unsigned long user_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_params extends Struct {
    public @Unsigned int sq_entries;

    public @Unsigned int cq_entries;

    public @Unsigned int flags;

    public @Unsigned int sq_thread_cpu;

    public @Unsigned int sq_thread_idle;

    public @Unsigned int features;

    public @Unsigned int wq_fd;

    public @Unsigned int @Size(3) [] resv;

    public io_sqring_offsets sq_off;

    public io_cqring_offsets cq_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_region_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_region_desc extends Struct {
    public @Unsigned long user_addr;

    public @Unsigned long size;

    public @Unsigned int flags;

    public @Unsigned int id;

    public @Unsigned long mmap_offset;

    public @Unsigned long @Size(4) [] __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_buf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_buf extends Struct {
    public @Unsigned long addr;

    public @Unsigned int len;

    public @Unsigned short bid;

    public @Unsigned short resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_buf_ring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_buf_ring extends Struct {
    @InlineUnion(31700)
    public anon_member_of_anon_member_of_io_uring_buf_ring anon0$0;

    @InlineUnion(31700)
    public anon_member_of_anon_member_of_io_uring_buf_ring anon0$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_reg_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_reg_wait extends Struct {
    public __kernel_timespec ts;

    public @Unsigned int min_wait_usec;

    public @Unsigned int flags;

    public @Unsigned long sigmask;

    public @Unsigned int sigmask_sz;

    public @Unsigned int @Size(3) [] pad;

    public @Unsigned long @Size(2) [] pad2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_getevents_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_getevents_arg extends Struct {
    public @Unsigned long sigmask;

    public @Unsigned int sigmask_sz;

    public @Unsigned int min_wait_usec;

    public @Unsigned long ts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rsrc_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rsrc_node extends Struct {
    public char type;

    public int refs;

    public @Unsigned long tag;

    @InlineUnion(31810)
    public @Unsigned long file_ptr;

    @InlineUnion(31810)
    public Ptr<io_mapped_ubuf> buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_sq_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_sq_data extends Struct {
    public @OriginalName("refcount_t") refcount_struct refs;

    public atomic_t park_pending;

    public mutex lock;

    public list_head ctx_list;

    public Ptr<task_struct> thread;

    public wait_queue_head wait;

    public @Unsigned int sq_thread_idle;

    public int sq_cpu;

    public @OriginalName("pid_t") int task_pid;

    public @OriginalName("pid_t") int task_tgid;

    public @Unsigned long work_time;

    public @Unsigned long state;

    public completion exited;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_buffer extends Struct {
    public list_head list;

    public @Unsigned long addr;

    public @Unsigned int len;

    public @Unsigned short bid;

    public @Unsigned short bgid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_buffer_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_buffer_list extends Struct {
    @InlineUnion(31832)
    public list_head buf_list;

    @InlineUnion(31832)
    public Ptr<io_uring_buf_ring> buf_ring;

    public int nbufs;

    public @Unsigned short bgid;

    public @Unsigned short buf_nr_pages;

    public @Unsigned short nr_entries;

    public @Unsigned short head;

    public @Unsigned short mask;

    public @Unsigned short flags;

    public io_mapped_region region;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_overflow_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_overflow_cqe extends Struct {
    public list_head list;

    public io_uring_cqe cqe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_wq_cancel"
  )
  public enum io_wq_cancel implements Enum<io_wq_cancel>, TypedEnum<io_wq_cancel, java.lang. @Unsigned Integer> {
    /**
     * {@code IO_WQ_CANCEL_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IO_WQ_CANCEL_OK"
    )
    IO_WQ_CANCEL_OK,

    /**
     * {@code IO_WQ_CANCEL_RUNNING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_WQ_CANCEL_RUNNING"
    )
    IO_WQ_CANCEL_RUNNING,

    /**
     * {@code IO_WQ_CANCEL_NOTFOUND = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IO_WQ_CANCEL_NOTFOUND"
    )
    IO_WQ_CANCEL_NOTFOUND
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_mapped_ubuf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_mapped_ubuf extends Struct {
    public @Unsigned long ubuf;

    public @Unsigned int len;

    public @Unsigned int nr_bvecs;

    public @Unsigned int folio_shift;

    public @OriginalName("refcount_t") refcount_struct refs;

    public @Unsigned long acct_pages;

    public Ptr<?> release;

    public Ptr<?> priv;

    public boolean is_kbuf;

    public char dir;

    public bio_vec @Size(0) [] bvec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_issue_def"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_issue_def extends Struct {
    public @Unsigned int needs_file;

    public @Unsigned int plug;

    public @Unsigned int ioprio;

    public @Unsigned int iopoll;

    public @Unsigned int buffer_select;

    public @Unsigned int hash_reg_file;

    public @Unsigned int unbound_nonreg_file;

    public @Unsigned int pollin;

    public @Unsigned int pollout;

    public @Unsigned int poll_exclusive;

    public @Unsigned int audit_skip;

    public @Unsigned int iopoll_queue;

    public @Unsigned int vectored;

    public @Unsigned short async_size;

    public Ptr<?> issue;

    public Ptr<?> prep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cold_def"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cold_def extends Struct {
    public String name;

    public Ptr<?> sqe_copy;

    public Ptr<?> cleanup;

    public Ptr<?> fail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wait_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wait_queue extends Struct {
    public wait_queue_entry wq;

    public Ptr<io_ring_ctx> ctx;

    public @Unsigned int cq_tail;

    public @Unsigned int cq_min_tail;

    public @Unsigned int nr_timeouts;

    public int hit_timeout;

    public @OriginalName("ktime_t") long min_timeout;

    public @OriginalName("ktime_t") long timeout;

    public hrtimer t;

    public @OriginalName("ktime_t") long napi_busy_poll_dt;

    public boolean napi_prefer_busy_poll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tctx_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tctx_node extends Struct {
    public list_head ctx_node;

    public Ptr<task_struct> task;

    public Ptr<io_ring_ctx> ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_poll"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_poll extends Struct {
    public Ptr<file> file;

    public Ptr<wait_queue_head> head;

    public @Unsigned @OriginalName("__poll_t") int events;

    public int retries;

    public wait_queue_entry wait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_defer_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_defer_entry extends Struct {
    public list_head list;

    public Ptr<io_kiocb> req;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_tctx_exit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_tctx_exit extends Struct {
    public callback_head task_work;

    public completion completion;

    public Ptr<io_ring_ctx> ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_task_cancel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_task_cancel extends Struct {
    public Ptr<io_uring_task> tctx;

    public boolean all;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_register_pbuf_ring_flags"
  )
  public enum io_uring_register_pbuf_ring_flags implements Enum<io_uring_register_pbuf_ring_flags>, TypedEnum<io_uring_register_pbuf_ring_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IOU_PBUF_RING_MMAP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IOU_PBUF_RING_MMAP"
    )
    IOU_PBUF_RING_MMAP,

    /**
     * {@code IOU_PBUF_RING_INC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IOU_PBUF_RING_INC"
    )
    IOU_PBUF_RING_INC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_buf_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_buf_reg extends Struct {
    public @Unsigned long ring_addr;

    public @Unsigned int ring_entries;

    public @Unsigned short bgid;

    public @Unsigned short flags;

    public @Unsigned long @Size(3) [] resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_buf_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_buf_status extends Struct {
    public @Unsigned int buf_group;

    public @Unsigned int head;

    public @Unsigned int @Size(8) [] resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_provide_buf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_provide_buf extends Struct {
    public Ptr<file> file;

    public @Unsigned long addr;

    public @Unsigned int len;

    public @Unsigned int bgid;

    public @Unsigned int nbufs;

    public @Unsigned short bid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_rsrc_register"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_rsrc_register extends Struct {
    public @Unsigned int nr;

    public @Unsigned int flags;

    public @Unsigned long resv2;

    public @Unsigned long data;

    public @Unsigned long tags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_rsrc_update2"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_rsrc_update2 extends Struct {
    public @Unsigned int offset;

    public @Unsigned int resv;

    public @Unsigned long data;

    public @Unsigned long tags;

    public @Unsigned int nr;

    public @Unsigned int resv2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_clone_buffers"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_clone_buffers extends Struct {
    public @Unsigned int src_fd;

    public @Unsigned int flags;

    public @Unsigned int src_off;

    public @Unsigned int dst_off;

    public @Unsigned int nr;

    public @Unsigned int @Size(3) [] pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_imu_folio_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_imu_folio_data extends Struct {
    public @Unsigned int nr_pages_head;

    public @Unsigned int nr_pages_mid;

    public @Unsigned int folio_shift;

    public @Unsigned int nr_folios;

    public @Unsigned long first_folio_page_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rsrc_update"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rsrc_update extends Struct {
    public Ptr<file> file;

    public @Unsigned long arg;

    public @Unsigned int nr_args;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_notif_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_notif_data extends Struct {
    public Ptr<file> file;

    public ubuf_info uarg;

    public Ptr<io_notif_data> next;

    public Ptr<io_notif_data> head;

    public @Unsigned int account_pages;

    public boolean zc_report;

    public boolean zc_used;

    public boolean zc_copied;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_rsrc_update"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_rsrc_update extends Struct {
    public @Unsigned int offset;

    public @Unsigned int resv;

    public @Unsigned long data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_data extends Struct {
    public Ptr<io_wq_hash> hash;

    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_file_index_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_file_index_range extends Struct {
    public @Unsigned int off;

    public @Unsigned int len;

    public @Unsigned long resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_attr_pi"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_attr_pi extends Struct {
    public @Unsigned short flags;

    public @Unsigned short app_tag;

    public @Unsigned int len;

    public @Unsigned long addr;

    public @Unsigned long seed;

    public @Unsigned long rsvd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_meta_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_meta_state extends Struct {
    public @Unsigned int seed;

    public iov_iter_state iter_meta;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_async_rw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_async_rw extends Struct {
    public iou_vec vec;

    public @Unsigned long bytes_done;

    @InlineUnion(31953)
    public anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw anon2$0;

    @InlineUnion(31953)
    public anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rw extends Struct {
    public kiocb kiocb;

    public @Unsigned long addr;

    public @Unsigned int len;

    public @OriginalName("rwf_t") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_napi_tracking_strategy"
  )
  public enum io_uring_napi_tracking_strategy implements Enum<io_uring_napi_tracking_strategy>, TypedEnum<io_uring_napi_tracking_strategy, java.lang. @Unsigned Integer> {
    /**
     * {@code IO_URING_NAPI_TRACKING_DYNAMIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IO_URING_NAPI_TRACKING_DYNAMIC"
    )
    IO_URING_NAPI_TRACKING_DYNAMIC,

    /**
     * {@code IO_URING_NAPI_TRACKING_STATIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_URING_NAPI_TRACKING_STATIC"
    )
    IO_URING_NAPI_TRACKING_STATIC,

    /**
     * {@code IO_URING_NAPI_TRACKING_INACTIVE = 255}
     */
    @EnumMember(
        value = 255L,
        name = "IO_URING_NAPI_TRACKING_INACTIVE"
    )
    IO_URING_NAPI_TRACKING_INACTIVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cancel_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cancel_data extends Struct {
    public Ptr<io_ring_ctx> ctx;

    @InlineUnion(31960)
    public @Unsigned long data;

    @InlineUnion(31960)
    public Ptr<file> file;

    public char opcode;

    public @Unsigned int flags;

    public int seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_poll_update"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_poll_update extends Struct {
    public Ptr<file> file;

    public @Unsigned long old_user_data;

    public @Unsigned long new_user_data;

    public @Unsigned @OriginalName("__poll_t") int events;

    public boolean update_events;

    public boolean update_user_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_poll_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_poll_table extends Struct {
    public poll_table_struct pt;

    public Ptr<io_kiocb> req;

    public int nr_entries;

    public int error;

    public boolean owning;

    public @Unsigned @OriginalName("__poll_t") int result_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_ev_fd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_ev_fd extends Struct {
    public Ptr<eventfd_ctx> cq_ev_fd;

    public @Unsigned int eventfd_async;

    public @Unsigned int last_cq_tail;

    public @OriginalName("refcount_t") refcount_struct refs;

    public atomic_t ops;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_async_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_async_cmd extends Struct {
    public iou_vec vec;

    public io_uring_sqe @Size(2) [] sqes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_open"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_open extends Struct {
    public Ptr<file> file;

    public int dfd;

    public @Unsigned int file_slot;

    public Ptr<filename> filename;

    public open_how how;

    public @Unsigned long nofile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_close"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_close extends Struct {
    public Ptr<file> file;

    public int fd;

    public @Unsigned int file_slot;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_fixed_install"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_fixed_install extends Struct {
    public Ptr<file> file;

    public @Unsigned int o_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pipe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pipe extends Struct {
    public Ptr<file> file;

    public Ptr<java.lang.Integer> fds;

    public int flags;

    public int file_slot;

    public @Unsigned long nofile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_sq_time"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_sq_time extends Struct {
    public boolean started;

    public @Unsigned long usec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_xattr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_xattr extends Struct {
    public Ptr<file> file;

    public kernel_xattr_ctx ctx;

    public Ptr<filename> filename;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_nop"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_nop extends Struct {
    public Ptr<file> file;

    public int result;

    public int fd;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_rename"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_rename extends Struct {
    public Ptr<file> file;

    public int old_dfd;

    public int new_dfd;

    public Ptr<filename> oldpath;

    public Ptr<filename> newpath;

    public int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_unlink"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_unlink extends Struct {
    public Ptr<file> file;

    public int dfd;

    public int flags;

    public Ptr<filename> filename;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_mkdir"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_mkdir extends Struct {
    public Ptr<file> file;

    public int dfd;

    public @Unsigned @OriginalName("umode_t") short mode;

    public Ptr<filename> filename;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_link extends Struct {
    public Ptr<file> file;

    public int old_dfd;

    public int new_dfd;

    public Ptr<filename> oldpath;

    public Ptr<filename> newpath;

    public int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_splice"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_splice extends Struct {
    public Ptr<file> file_out;

    public @OriginalName("loff_t") long off_out;

    public @OriginalName("loff_t") long off_in;

    public @Unsigned long len;

    public int splice_fd_in;

    public @Unsigned int flags;

    public Ptr<io_rsrc_node> rsrc_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_sync"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_sync extends Struct {
    public Ptr<file> file;

    public @OriginalName("loff_t") long len;

    public @OriginalName("loff_t") long off;

    public int flags;

    public int mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_msg_ring_flags"
  )
  public enum io_uring_msg_ring_flags implements Enum<io_uring_msg_ring_flags>, TypedEnum<io_uring_msg_ring_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IORING_MSG_DATA = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IORING_MSG_DATA"
    )
    IORING_MSG_DATA,

    /**
     * {@code IORING_MSG_SEND_FD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IORING_MSG_SEND_FD"
    )
    IORING_MSG_SEND_FD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_msg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_msg extends Struct {
    public Ptr<file> file;

    public Ptr<file> src_file;

    public callback_head tw;

    public @Unsigned long user_data;

    public @Unsigned int len;

    public @Unsigned int cmd;

    public @Unsigned int src_fd;

    @InlineUnion(32010)
    public @Unsigned int dst_fd;

    @InlineUnion(32010)
    public @Unsigned int cqe_flags;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_fadvise"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_fadvise extends Struct {
    public Ptr<file> file;

    public @Unsigned long offset;

    public @Unsigned long len;

    public @Unsigned int advice;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_madvise"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_madvise extends Struct {
    public Ptr<file> file;

    public @Unsigned long addr;

    public @Unsigned long len;

    public @Unsigned int advice;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_statx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_statx extends Struct {
    public Ptr<file> file;

    public int dfd;

    public @Unsigned int mask;

    public @Unsigned int flags;

    public Ptr<filename> filename;

    public Ptr<statx> buffer;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_timeout_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_timeout_data extends Struct {
    public Ptr<io_kiocb> req;

    public hrtimer timer;

    public timespec64 ts;

    public hrtimer_mode mode;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_timeout"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_timeout extends Struct {
    public Ptr<file> file;

    public @Unsigned int off;

    public @Unsigned int target_seq;

    public @Unsigned int repeats;

    public list_head list;

    public Ptr<io_kiocb> head;

    public Ptr<io_kiocb> prev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_timeout_rem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_timeout_rem extends Struct {
    public Ptr<file> file;

    public @Unsigned long addr;

    public timespec64 ts;

    public @Unsigned int flags;

    public boolean ltimeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_sync_cancel_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_sync_cancel_reg extends Struct {
    public @Unsigned long addr;

    public int fd;

    public @Unsigned int flags;

    public __kernel_timespec timeout;

    public char opcode;

    public char @Size(7) [] pad;

    public @Unsigned long @Size(3) [] pad2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cancel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cancel extends Struct {
    public Ptr<file> file;

    public @Unsigned long addr;

    public @Unsigned int flags;

    public int fd;

    public char opcode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_waitid_async"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_waitid_async extends Struct {
    public Ptr<io_kiocb> req;

    public wait_opts wo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_waitid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_waitid extends Struct {
    public Ptr<file> file;

    public int which;

    public @OriginalName("pid_t") int upid;

    public int options;

    public atomic_t refs;

    public Ptr<wait_queue_head> head;

    public Ptr<siginfo> infop;

    public waitid_info info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_mem_region_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_mem_region_reg extends Struct {
    public @Unsigned long region_uptr;

    public @Unsigned long flags;

    public @Unsigned long @Size(2) [] __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_probe_op"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_probe_op extends Struct {
    public char op;

    public char resv;

    public @Unsigned short flags;

    public @Unsigned int resv2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_probe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_probe extends Struct {
    public char last_op;

    public char ops_len;

    public @Unsigned short resv;

    public @Unsigned int @Size(3) [] resv2;

    public io_uring_probe_op @Size(0) [] ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_restriction"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_restriction extends Struct {
    public @Unsigned short opcode;

    @InlineUnion(32039)
    public char register_op;

    @InlineUnion(32039)
    public char sqe_op;

    @InlineUnion(32039)
    public char sqe_flags;

    public char resv;

    public @Unsigned int @Size(3) [] resv2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_clock_register"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_clock_register extends Struct {
    public @Unsigned int clockid;

    public @Unsigned int @Size(3) [] __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_register_restriction_op"
  )
  public enum io_uring_register_restriction_op implements Enum<io_uring_register_restriction_op>, TypedEnum<io_uring_register_restriction_op, java.lang. @Unsigned Integer> {
    /**
     * {@code IORING_RESTRICTION_REGISTER_OP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IORING_RESTRICTION_REGISTER_OP"
    )
    IORING_RESTRICTION_REGISTER_OP,

    /**
     * {@code IORING_RESTRICTION_SQE_OP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IORING_RESTRICTION_SQE_OP"
    )
    IORING_RESTRICTION_SQE_OP,

    /**
     * {@code IORING_RESTRICTION_SQE_FLAGS_ALLOWED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IORING_RESTRICTION_SQE_FLAGS_ALLOWED"
    )
    IORING_RESTRICTION_SQE_FLAGS_ALLOWED,

    /**
     * {@code IORING_RESTRICTION_SQE_FLAGS_REQUIRED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IORING_RESTRICTION_SQE_FLAGS_REQUIRED"
    )
    IORING_RESTRICTION_SQE_FLAGS_REQUIRED,

    /**
     * {@code IORING_RESTRICTION_LAST = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IORING_RESTRICTION_LAST"
    )
    IORING_RESTRICTION_LAST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_zcrx_offsets"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_zcrx_offsets extends Struct {
    public @Unsigned int head;

    public @Unsigned int tail;

    public @Unsigned int rqes;

    public @Unsigned int __resv2;

    public @Unsigned long @Size(2) [] __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_zcrx_ifq_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_zcrx_ifq_reg extends Struct {
    public @Unsigned int if_idx;

    public @Unsigned int if_rxq;

    public @Unsigned int rq_entries;

    public @Unsigned int flags;

    public @Unsigned long area_ptr;

    public @Unsigned long region_ptr;

    public io_uring_zcrx_offsets offsets;

    public @Unsigned int zcrx_id;

    public @Unsigned int __resv2;

    public @Unsigned long @Size(3) [] __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_ring_ctx_rings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_ring_ctx_rings extends Struct {
    public Ptr<io_rings> rings;

    public Ptr<io_uring_sqe> sq_sqes;

    public io_mapped_region sq_region;

    public io_mapped_region ring_region;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_ftrunc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_ftrunc extends Struct {
    public Ptr<file> file;

    public @OriginalName("loff_t") long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_zcrx_rqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_zcrx_rqe extends Struct {
    public @Unsigned long off;

    public @Unsigned int len;

    public @Unsigned int __pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_zcrx_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_zcrx_cqe extends Struct {
    public @Unsigned long off;

    public @Unsigned long __pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_zcrx_area_flags"
  )
  public enum io_uring_zcrx_area_flags implements Enum<io_uring_zcrx_area_flags>, TypedEnum<io_uring_zcrx_area_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IORING_ZCRX_AREA_DMABUF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IORING_ZCRX_AREA_DMABUF"
    )
    IORING_ZCRX_AREA_DMABUF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_zcrx_area_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_zcrx_area_reg extends Struct {
    public @Unsigned long addr;

    public @Unsigned long len;

    public @Unsigned long rq_area_token;

    public @Unsigned int flags;

    public @Unsigned int dmabuf_fd;

    public @Unsigned long @Size(2) [] __resv2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_zcrx_mem"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_zcrx_mem extends Struct {
    public @Unsigned long size;

    public boolean is_dmabuf;

    public Ptr<Ptr<page>> pages;

    public @Unsigned long nr_folios;

    public sg_table page_sg_table;

    public @Unsigned long account_pages;

    public Ptr<dma_buf_attachment> attach;

    public Ptr<dma_buf> dmabuf;

    public Ptr<sg_table> sgt;

    public @Unsigned long dmabuf_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_zcrx_area"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_zcrx_area extends Struct {
    public net_iov_area nia;

    public Ptr<io_zcrx_ifq> ifq;

    public Ptr<atomic_t> user_refs;

    public boolean is_mapped;

    public @Unsigned short area_id;

    public @OriginalName("spinlock_t") spinlock freelist_lock;

    public @Unsigned int free_count;

    public Ptr<java.lang. @Unsigned Integer> freelist;

    public io_zcrx_mem mem;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_zcrx_ifq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_zcrx_ifq extends Struct {
    public Ptr<io_ring_ctx> ctx;

    public Ptr<io_zcrx_area> area;

    public @OriginalName("spinlock_t") spinlock rq_lock;

    public Ptr<io_uring> rq_ring;

    public Ptr<io_uring_zcrx_rqe> rqes;

    public @Unsigned int cached_rq_head;

    public @Unsigned int rq_entries;

    public @Unsigned int if_rxq;

    public Ptr<device> dev;

    public Ptr<net_device> netdev;

    public @OriginalName("netdevice_tracker") lockdep_map_p netdev_tracker;

    public @OriginalName("spinlock_t") spinlock lock;

    public mutex dma_lock;

    public io_mapped_region region;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_zcrx_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_zcrx_args extends Struct {
    public Ptr<io_kiocb> req;

    public Ptr<io_zcrx_ifq> ifq;

    public Ptr<socket> sock;

    public @Unsigned int nr_skbs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_copy_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_copy_cache extends Struct {
    public Ptr<page> page;

    public @Unsigned long offset;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_wq_type"
  )
  public enum io_wq_type implements Enum<io_wq_type>, TypedEnum<io_wq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IO_WQ_BOUND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IO_WQ_BOUND"
    )
    IO_WQ_BOUND,

    /**
     * {@code IO_WQ_UNBOUND = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_WQ_UNBOUND"
    )
    IO_WQ_UNBOUND
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq extends Struct {
    public @Unsigned long state;

    public Ptr<io_wq_hash> hash;

    public atomic_t worker_refs;

    public completion worker_done;

    public hlist_node cpuhp_node;

    public Ptr<task_struct> task;

    public io_wq_acct @Size(2) [] acct;

    public wait_queue_entry wait;

    public Ptr<io_wq_work> @Size(64) [] hash_tail;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpu_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_worker"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_worker extends Struct {
    public @OriginalName("refcount_t") refcount_struct ref;

    public @Unsigned long flags;

    public hlist_nulls_node nulls_node;

    public list_head all_list;

    public Ptr<task_struct> task;

    public Ptr<io_wq> wq;

    public Ptr<io_wq_acct> acct;

    public Ptr<io_wq_work> cur_work;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public completion ref_done;

    public @Unsigned long create_state;

    public callback_head create_work;

    public int init_retries;

    @InlineUnion(32140)
    public callback_head rcu;

    @InlineUnion(32140)
    public delayed_work work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_wq_acct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_wq_acct extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock workers_lock;

    public @Unsigned int nr_workers;

    public @Unsigned int max_workers;

    public atomic_t nr_running;

    public hlist_nulls_head free_list;

    public list_head all_list;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public io_wq_work_list work_list;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_cb_cancel_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_cb_cancel_data extends Struct {
    public Ptr<?> fn;

    public Ptr<?> data;

    public int nr_running;

    public int nr_pending;

    public boolean cancel_all;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_futex"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_futex extends Struct {
    public Ptr<file> file;

    public Ptr<?> uaddr;

    public @Unsigned long futex_val;

    public @Unsigned long futex_mask;

    public @Unsigned long futexv_owned;

    public @Unsigned int futex_flags;

    public @Unsigned int futex_nr;

    public boolean futexv_unqueued;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_futex_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_futex_data extends Struct {
    public futex_q q;

    public Ptr<io_kiocb> req;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_epoll"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_epoll extends Struct {
    public Ptr<file> file;

    public int epfd;

    public int op;

    public int fd;

    public epoll_event event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_epoll_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_epoll_wait extends Struct {
    public Ptr<file> file;

    public int maxevents;

    public Ptr<epoll_event> events;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_napi_op"
  )
  public enum io_uring_napi_op implements Enum<io_uring_napi_op>, TypedEnum<io_uring_napi_op, java.lang. @Unsigned Integer> {
    /**
     * {@code IO_URING_NAPI_REGISTER_OP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IO_URING_NAPI_REGISTER_OP"
    )
    IO_URING_NAPI_REGISTER_OP,

    /**
     * {@code IO_URING_NAPI_STATIC_ADD_ID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_URING_NAPI_STATIC_ADD_ID"
    )
    IO_URING_NAPI_STATIC_ADD_ID,

    /**
     * {@code IO_URING_NAPI_STATIC_DEL_ID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IO_URING_NAPI_STATIC_DEL_ID"
    )
    IO_URING_NAPI_STATIC_DEL_ID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_napi"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_napi extends Struct {
    public @Unsigned int busy_poll_to;

    public char prefer_busy_poll;

    public char opcode;

    public char @Size(2) [] pad;

    public @Unsigned int op_param;

    public @Unsigned int resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_napi_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_napi_entry extends Struct {
    public @Unsigned int napi_id;

    public list_head list;

    public @Unsigned long timeout;

    public hlist_node node;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_uring_recvmsg_out"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_uring_recvmsg_out extends Struct {
    public @Unsigned int namelen;

    public @Unsigned int controllen;

    public @Unsigned int payloadlen;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_async_msghdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_async_msghdr extends Struct {
    public iou_vec vec;

    @InlineUnion(32173)
    public anon_member_of_anon_member_of_io_async_msghdr_and_clear_of_anon_member_of_io_async_msghdr anon1$0;

    @InlineUnion(32173)
    public anon_member_of_anon_member_of_io_async_msghdr_and_clear_of_anon_member_of_io_async_msghdr clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_shutdown"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_shutdown extends Struct {
    public Ptr<file> file;

    public int how;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_accept"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_accept extends Struct {
    public Ptr<file> file;

    public Ptr<sockaddr> addr;

    public Ptr<java.lang.Integer> addr_len;

    public int flags;

    public int iou_flags;

    public @Unsigned int file_slot;

    public @Unsigned long nofile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_socket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_socket extends Struct {
    public Ptr<file> file;

    public int domain;

    public int type;

    public int protocol;

    public int flags;

    public @Unsigned int file_slot;

    public @Unsigned long nofile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_connect"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_connect extends Struct {
    public Ptr<file> file;

    public Ptr<sockaddr> addr;

    public int addr_len;

    public boolean in_progress;

    public boolean seen_econnaborted;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_bind"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_bind extends Struct {
    public Ptr<file> file;

    public int addr_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_listen"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_listen extends Struct {
    public Ptr<file> file;

    public int backlog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_sr_msg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_sr_msg extends Struct {
    public Ptr<file> file;

    @InlineUnion(32181)
    public Ptr<compat_msghdr> umsg_compat;

    @InlineUnion(32181)
    public Ptr<user_msghdr> umsg;

    @InlineUnion(32181)
    public Ptr<?> buf;

    public int len;

    public @Unsigned int done_io;

    public @Unsigned int msg_flags;

    public @Unsigned int nr_multishot_loops;

    public @Unsigned short flags;

    public @Unsigned short buf_group;

    public @Unsigned int mshot_len;

    public @Unsigned int mshot_total_len;

    public Ptr<?> msg_control;

    public Ptr<io_kiocb> notif;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_recvzc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_recvzc extends Struct {
    public Ptr<file> file;

    public @Unsigned int msg_flags;

    public @Unsigned short flags;

    public @Unsigned int len;

    public Ptr<io_zcrx_ifq> ifq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_recvmsg_multishot_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_recvmsg_multishot_hdr extends Struct {
    public io_uring_recvmsg_out msg;

    public __kernel_sockaddr_storage addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_uring_socket_op"
  )
  public enum io_uring_socket_op implements Enum<io_uring_socket_op>, TypedEnum<io_uring_socket_op, java.lang. @Unsigned Integer> {
    /**
     * {@code SOCKET_URING_OP_SIOCINQ = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SOCKET_URING_OP_SIOCINQ"
    )
    SOCKET_URING_OP_SIOCINQ,

    /**
     * {@code SOCKET_URING_OP_SIOCOUTQ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SOCKET_URING_OP_SIOCOUTQ"
    )
    SOCKET_URING_OP_SIOCOUTQ,

    /**
     * {@code SOCKET_URING_OP_GETSOCKOPT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SOCKET_URING_OP_GETSOCKOPT"
    )
    SOCKET_URING_OP_GETSOCKOPT,

    /**
     * {@code SOCKET_URING_OP_SETSOCKOPT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SOCKET_URING_OP_SETSOCKOPT"
    )
    SOCKET_URING_OP_SETSOCKOPT,

    /**
     * {@code SOCKET_URING_OP_TX_TIMESTAMP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SOCKET_URING_OP_TX_TIMESTAMP"
    )
    SOCKET_URING_OP_TX_TIMESTAMP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_timespec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_timespec extends Struct {
    public @Unsigned long tv_sec;

    public @Unsigned long tv_nsec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pagetable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pagetable extends Struct {
    public rw_semaphore domains_rwsem;

    public xarray domains;

    public xarray access_list;

    public @Unsigned int next_domain_id;

    public rw_semaphore iova_rwsem;

    public rb_root_cached area_itree;

    public rb_root_cached allowed_itree;

    public rb_root_cached reserved_itree;

    public char disable_large_pages;

    public @Unsigned long iova_alignment;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_pgtable_fmt"
  )
  public enum io_pgtable_fmt implements Enum<io_pgtable_fmt>, TypedEnum<io_pgtable_fmt, java.lang. @Unsigned Integer> {
    /**
     * {@code ARM_32_LPAE_S1 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ARM_32_LPAE_S1"
    )
    ARM_32_LPAE_S1,

    /**
     * {@code ARM_32_LPAE_S2 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ARM_32_LPAE_S2"
    )
    ARM_32_LPAE_S2,

    /**
     * {@code ARM_64_LPAE_S1 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ARM_64_LPAE_S1"
    )
    ARM_64_LPAE_S1,

    /**
     * {@code ARM_64_LPAE_S2 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ARM_64_LPAE_S2"
    )
    ARM_64_LPAE_S2,

    /**
     * {@code ARM_V7S = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ARM_V7S"
    )
    ARM_V7S,

    /**
     * {@code ARM_MALI_LPAE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ARM_MALI_LPAE"
    )
    ARM_MALI_LPAE,

    /**
     * {@code AMD_IOMMU_V1 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "AMD_IOMMU_V1"
    )
    AMD_IOMMU_V1,

    /**
     * {@code AMD_IOMMU_V2 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "AMD_IOMMU_V2"
    )
    AMD_IOMMU_V2,

    /**
     * {@code APPLE_DART = 8}
     */
    @EnumMember(
        value = 8L,
        name = "APPLE_DART"
    )
    APPLE_DART,

    /**
     * {@code APPLE_DART2 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "APPLE_DART2"
    )
    APPLE_DART2,

    /**
     * {@code IO_PGTABLE_NUM_FMTS = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IO_PGTABLE_NUM_FMTS"
    )
    IO_PGTABLE_NUM_FMTS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pgtable_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pgtable_cfg extends Struct {
    public @Unsigned long quirks;

    public @Unsigned long pgsize_bitmap;

    public @Unsigned int ias;

    public @Unsigned int oas;

    public boolean coherent_walk;

    public Ptr<iommu_flush_ops> tlb;

    public Ptr<device> iommu_dev;

    public Ptr<?> alloc;

    public Ptr<?> free;

    @InlineUnion(43527)
    public arm_lpae_s1_cfg_of_anon_member_of_io_pgtable_cfg arm_lpae_s1_cfg;

    @InlineUnion(43527)
    public arm_lpae_s2_cfg_of_anon_member_of_io_pgtable_cfg arm_lpae_s2_cfg;

    @InlineUnion(43527)
    public arm_v7s_cfg_of_anon_member_of_io_pgtable_cfg arm_v7s_cfg;

    @InlineUnion(43527)
    public arm_mali_lpae_cfg_of_anon_member_of_io_pgtable_cfg arm_mali_lpae_cfg;

    @InlineUnion(43527)
    public apple_dart_cfg_of_anon_member_of_io_pgtable_cfg apple_dart_cfg;

    @InlineUnion(43527)
    public amd_of_anon_member_of_io_pgtable_cfg amd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pgtable_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pgtable_ops extends Struct {
    public Ptr<?> map_pages;

    public Ptr<?> unmap_pages;

    public Ptr<?> iova_to_phys;

    public Ptr<?> pgtable_walk;

    public Ptr<?> read_and_clear_dirty;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pgtable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pgtable extends Struct {
    public io_pgtable_fmt fmt;

    public Ptr<?> cookie;

    public io_pgtable_cfg cfg;

    public io_pgtable_ops ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_pgtable_init_fns"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_pgtable_init_fns extends Struct {
    public Ptr<?> alloc;

    public Ptr<?> free;

    public @Unsigned int caps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum io_pgtable_caps"
  )
  public enum io_pgtable_caps implements Enum<io_pgtable_caps>, TypedEnum<io_pgtable_caps, java.lang. @Unsigned Integer> {
    /**
     * {@code IO_PGTABLE_CAP_CUSTOM_ALLOCATOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IO_PGTABLE_CAP_CUSTOM_ALLOCATOR"
    )
    IO_PGTABLE_CAP_CUSTOM_ALLOCATOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct io_err_c"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class io_err_c extends Struct {
    public Ptr<dm_dev> dev;

    public @Unsigned @OriginalName("sector_t") long start;
  }
}
