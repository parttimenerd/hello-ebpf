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
 * Generated class for BPF runtime types that start with opal
 */
@java.lang.SuppressWarnings("unused")
public final class OpalDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __opal_lock_unlock(Ptr<opal_dev> dev, Ptr<opal_lock_unlock> lk_unlk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int opal_discovery0(Ptr<opal_dev> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int opal_discovery0_end(Ptr<opal_dev> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void opal_lock_check_for_saved_key(Ptr<opal_dev> dev,
      Ptr<opal_lock_unlock> lk_unlk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int opal_reverttper(Ptr<opal_dev> dev, Ptr<opal_key> opal, boolean psid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean opal_unlock_from_suspend(Ptr<opal_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_mbr"
  )
  public enum opal_mbr implements Enum<opal_mbr>, TypedEnum<opal_mbr, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_MBR_ENABLE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_MBR_ENABLE"
    )
    OPAL_MBR_ENABLE,

    /**
     * {@code OPAL_MBR_DISABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_MBR_DISABLE"
    )
    OPAL_MBR_DISABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_mbr_done_flag"
  )
  public enum opal_mbr_done_flag implements Enum<opal_mbr_done_flag>, TypedEnum<opal_mbr_done_flag, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_MBR_NOT_DONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_MBR_NOT_DONE"
    )
    OPAL_MBR_NOT_DONE,

    /**
     * {@code OPAL_MBR_DONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_MBR_DONE"
    )
    OPAL_MBR_DONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_user"
  )
  public enum opal_user implements Enum<opal_user>, TypedEnum<opal_user, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_ADMIN1 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_ADMIN1"
    )
    OPAL_ADMIN1,

    /**
     * {@code OPAL_USER1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_USER1"
    )
    OPAL_USER1,

    /**
     * {@code OPAL_USER2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_USER2"
    )
    OPAL_USER2,

    /**
     * {@code OPAL_USER3 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_USER3"
    )
    OPAL_USER3,

    /**
     * {@code OPAL_USER4 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_USER4"
    )
    OPAL_USER4,

    /**
     * {@code OPAL_USER5 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OPAL_USER5"
    )
    OPAL_USER5,

    /**
     * {@code OPAL_USER6 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_USER6"
    )
    OPAL_USER6,

    /**
     * {@code OPAL_USER7 = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OPAL_USER7"
    )
    OPAL_USER7,

    /**
     * {@code OPAL_USER8 = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OPAL_USER8"
    )
    OPAL_USER8,

    /**
     * {@code OPAL_USER9 = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OPAL_USER9"
    )
    OPAL_USER9
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_lock_state"
  )
  public enum opal_lock_state implements Enum<opal_lock_state>, TypedEnum<opal_lock_state, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_RO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_RO"
    )
    OPAL_RO,

    /**
     * {@code OPAL_RW = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_RW"
    )
    OPAL_RW,

    /**
     * {@code OPAL_LK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_LK"
    )
    OPAL_LK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_lock_flags"
  )
  public enum opal_lock_flags implements Enum<opal_lock_flags>, TypedEnum<opal_lock_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_SAVE_FOR_LOCK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_SAVE_FOR_LOCK"
    )
    OPAL_SAVE_FOR_LOCK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_key_type"
  )
  public enum opal_key_type implements Enum<opal_key_type>, TypedEnum<opal_key_type, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_INCLUDED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_INCLUDED"
    )
    OPAL_INCLUDED,

    /**
     * {@code OPAL_KEYRING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_KEYRING"
    )
    OPAL_KEYRING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_key extends Struct {
    public char lr;

    public char key_len;

    public char key_type;

    public char @Size(5) [] __align;

    public char @Size(256) [] key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_revert_lsp_opts"
  )
  public enum opal_revert_lsp_opts implements Enum<opal_revert_lsp_opts>, TypedEnum<opal_revert_lsp_opts, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_PRESERVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_PRESERVE"
    )
    OPAL_PRESERVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_lr_act"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_lr_act extends Struct {
    public opal_key key;

    public @Unsigned int sum;

    public char num_lrs;

    public char @Size(9) [] lr;

    public char @Size(2) [] align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_session_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_session_info extends Struct {
    public @Unsigned int sum;

    public @Unsigned int who;

    public opal_key opal_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_user_lr_setup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_user_lr_setup extends Struct {
    public @Unsigned long range_start;

    public @Unsigned long range_length;

    public @Unsigned int RLE;

    public @Unsigned int WLE;

    public opal_session_info session;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_lr_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_lr_status extends Struct {
    public opal_session_info session;

    public @Unsigned long range_start;

    public @Unsigned long range_length;

    public @Unsigned int RLE;

    public @Unsigned int WLE;

    public @Unsigned int l_state;

    public char @Size(4) [] align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_lock_unlock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_lock_unlock extends Struct {
    public opal_session_info session;

    public @Unsigned int l_state;

    public @Unsigned short flags;

    public char @Size(2) [] __align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_new_pw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_new_pw extends Struct {
    public opal_session_info session;

    public opal_session_info new_user_pw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_mbr_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_mbr_data extends Struct {
    public opal_key key;

    public char enable_disable;

    public char @Size(7) [] __align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_mbr_done"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_mbr_done extends Struct {
    public opal_key key;

    public char done_flag;

    public char @Size(7) [] __align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_shadow_mbr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_shadow_mbr extends Struct {
    public opal_key key;

    public @Unsigned long data;

    public @Unsigned long offset;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_table_ops"
  )
  public enum opal_table_ops implements Enum<opal_table_ops>, TypedEnum<opal_table_ops, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_READ_TABLE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_READ_TABLE"
    )
    OPAL_READ_TABLE,

    /**
     * {@code OPAL_WRITE_TABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_WRITE_TABLE"
    )
    OPAL_WRITE_TABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_read_write_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_read_write_table extends Struct {
    public opal_key key;

    public @Unsigned long data;

    public char @Size(8) [] table_uid;

    public @Unsigned long offset;

    public @Unsigned long size;

    public @Unsigned long flags;

    public @Unsigned long priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_status extends Struct {
    public @Unsigned int flags;

    public @Unsigned int reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_geometry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_geometry extends Struct {
    public char align;

    public @Unsigned int logical_block_size;

    public @Unsigned long alignment_granularity;

    public @Unsigned long lowest_aligned_lba;

    public char @Size(3) [] __align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_discovery"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_discovery extends Struct {
    public @Unsigned long data;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_revert_lsp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_revert_lsp extends Struct {
    public opal_key key;

    public @Unsigned int options;

    public @Unsigned int __pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_response_token"
  )
  public enum opal_response_token implements Enum<opal_response_token>, TypedEnum<opal_response_token, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_DTA_TOKENID_BYTESTRING = 224}
     */
    @EnumMember(
        value = 224L,
        name = "OPAL_DTA_TOKENID_BYTESTRING"
    )
    OPAL_DTA_TOKENID_BYTESTRING,

    /**
     * {@code OPAL_DTA_TOKENID_SINT = 225}
     */
    @EnumMember(
        value = 225L,
        name = "OPAL_DTA_TOKENID_SINT"
    )
    OPAL_DTA_TOKENID_SINT,

    /**
     * {@code OPAL_DTA_TOKENID_UINT = 226}
     */
    @EnumMember(
        value = 226L,
        name = "OPAL_DTA_TOKENID_UINT"
    )
    OPAL_DTA_TOKENID_UINT,

    /**
     * {@code OPAL_DTA_TOKENID_TOKEN = 227}
     */
    @EnumMember(
        value = 227L,
        name = "OPAL_DTA_TOKENID_TOKEN"
    )
    OPAL_DTA_TOKENID_TOKEN,

    /**
     * {@code OPAL_DTA_TOKENID_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_DTA_TOKENID_INVALID"
    )
    OPAL_DTA_TOKENID_INVALID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_uid"
  )
  public enum opal_uid implements Enum<opal_uid>, TypedEnum<opal_uid, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_SMUID_UID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_SMUID_UID"
    )
    OPAL_SMUID_UID,

    /**
     * {@code OPAL_THISSP_UID = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_THISSP_UID"
    )
    OPAL_THISSP_UID,

    /**
     * {@code OPAL_ADMINSP_UID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_ADMINSP_UID"
    )
    OPAL_ADMINSP_UID,

    /**
     * {@code OPAL_LOCKINGSP_UID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_LOCKINGSP_UID"
    )
    OPAL_LOCKINGSP_UID,

    /**
     * {@code OPAL_ENTERPRISE_LOCKINGSP_UID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_ENTERPRISE_LOCKINGSP_UID"
    )
    OPAL_ENTERPRISE_LOCKINGSP_UID,

    /**
     * {@code OPAL_ANYBODY_UID = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OPAL_ANYBODY_UID"
    )
    OPAL_ANYBODY_UID,

    /**
     * {@code OPAL_SID_UID = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_SID_UID"
    )
    OPAL_SID_UID,

    /**
     * {@code OPAL_ADMIN1_UID = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OPAL_ADMIN1_UID"
    )
    OPAL_ADMIN1_UID,

    /**
     * {@code OPAL_USER1_UID = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OPAL_USER1_UID"
    )
    OPAL_USER1_UID,

    /**
     * {@code OPAL_USER2_UID = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OPAL_USER2_UID"
    )
    OPAL_USER2_UID,

    /**
     * {@code OPAL_PSID_UID = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OPAL_PSID_UID"
    )
    OPAL_PSID_UID,

    /**
     * {@code OPAL_ENTERPRISE_BANDMASTER0_UID = 11}
     */
    @EnumMember(
        value = 11L,
        name = "OPAL_ENTERPRISE_BANDMASTER0_UID"
    )
    OPAL_ENTERPRISE_BANDMASTER0_UID,

    /**
     * {@code OPAL_ENTERPRISE_ERASEMASTER_UID = 12}
     */
    @EnumMember(
        value = 12L,
        name = "OPAL_ENTERPRISE_ERASEMASTER_UID"
    )
    OPAL_ENTERPRISE_ERASEMASTER_UID,

    /**
     * {@code OPAL_TABLE_TABLE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "OPAL_TABLE_TABLE"
    )
    OPAL_TABLE_TABLE,

    /**
     * {@code OPAL_LOCKINGRANGE_GLOBAL = 14}
     */
    @EnumMember(
        value = 14L,
        name = "OPAL_LOCKINGRANGE_GLOBAL"
    )
    OPAL_LOCKINGRANGE_GLOBAL,

    /**
     * {@code OPAL_LOCKINGRANGE_ACE_START_TO_KEY = 15}
     */
    @EnumMember(
        value = 15L,
        name = "OPAL_LOCKINGRANGE_ACE_START_TO_KEY"
    )
    OPAL_LOCKINGRANGE_ACE_START_TO_KEY,

    /**
     * {@code OPAL_LOCKINGRANGE_ACE_RDLOCKED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "OPAL_LOCKINGRANGE_ACE_RDLOCKED"
    )
    OPAL_LOCKINGRANGE_ACE_RDLOCKED,

    /**
     * {@code OPAL_LOCKINGRANGE_ACE_WRLOCKED = 17}
     */
    @EnumMember(
        value = 17L,
        name = "OPAL_LOCKINGRANGE_ACE_WRLOCKED"
    )
    OPAL_LOCKINGRANGE_ACE_WRLOCKED,

    /**
     * {@code OPAL_MBRCONTROL = 18}
     */
    @EnumMember(
        value = 18L,
        name = "OPAL_MBRCONTROL"
    )
    OPAL_MBRCONTROL,

    /**
     * {@code OPAL_MBR = 19}
     */
    @EnumMember(
        value = 19L,
        name = "OPAL_MBR"
    )
    OPAL_MBR,

    /**
     * {@code OPAL_AUTHORITY_TABLE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "OPAL_AUTHORITY_TABLE"
    )
    OPAL_AUTHORITY_TABLE,

    /**
     * {@code OPAL_C_PIN_TABLE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "OPAL_C_PIN_TABLE"
    )
    OPAL_C_PIN_TABLE,

    /**
     * {@code OPAL_LOCKING_INFO_TABLE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "OPAL_LOCKING_INFO_TABLE"
    )
    OPAL_LOCKING_INFO_TABLE,

    /**
     * {@code OPAL_ENTERPRISE_LOCKING_INFO_TABLE = 23}
     */
    @EnumMember(
        value = 23L,
        name = "OPAL_ENTERPRISE_LOCKING_INFO_TABLE"
    )
    OPAL_ENTERPRISE_LOCKING_INFO_TABLE,

    /**
     * {@code OPAL_DATASTORE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "OPAL_DATASTORE"
    )
    OPAL_DATASTORE,

    /**
     * {@code OPAL_C_PIN_MSID = 25}
     */
    @EnumMember(
        value = 25L,
        name = "OPAL_C_PIN_MSID"
    )
    OPAL_C_PIN_MSID,

    /**
     * {@code OPAL_C_PIN_SID = 26}
     */
    @EnumMember(
        value = 26L,
        name = "OPAL_C_PIN_SID"
    )
    OPAL_C_PIN_SID,

    /**
     * {@code OPAL_C_PIN_ADMIN1 = 27}
     */
    @EnumMember(
        value = 27L,
        name = "OPAL_C_PIN_ADMIN1"
    )
    OPAL_C_PIN_ADMIN1,

    /**
     * {@code OPAL_HALF_UID_AUTHORITY_OBJ_REF = 28}
     */
    @EnumMember(
        value = 28L,
        name = "OPAL_HALF_UID_AUTHORITY_OBJ_REF"
    )
    OPAL_HALF_UID_AUTHORITY_OBJ_REF,

    /**
     * {@code OPAL_HALF_UID_BOOLEAN_ACE = 29}
     */
    @EnumMember(
        value = 29L,
        name = "OPAL_HALF_UID_BOOLEAN_ACE"
    )
    OPAL_HALF_UID_BOOLEAN_ACE,

    /**
     * {@code OPAL_UID_HEXFF = 30}
     */
    @EnumMember(
        value = 30L,
        name = "OPAL_UID_HEXFF"
    )
    OPAL_UID_HEXFF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_method"
  )
  public enum opal_method implements Enum<opal_method>, TypedEnum<opal_method, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_PROPERTIES = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_PROPERTIES"
    )
    OPAL_PROPERTIES,

    /**
     * {@code OPAL_STARTSESSION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_STARTSESSION"
    )
    OPAL_STARTSESSION,

    /**
     * {@code OPAL_REVERT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_REVERT"
    )
    OPAL_REVERT,

    /**
     * {@code OPAL_ACTIVATE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_ACTIVATE"
    )
    OPAL_ACTIVATE,

    /**
     * {@code OPAL_EGET = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_EGET"
    )
    OPAL_EGET,

    /**
     * {@code OPAL_ESET = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OPAL_ESET"
    )
    OPAL_ESET,

    /**
     * {@code OPAL_NEXT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_NEXT"
    )
    OPAL_NEXT,

    /**
     * {@code OPAL_EAUTHENTICATE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OPAL_EAUTHENTICATE"
    )
    OPAL_EAUTHENTICATE,

    /**
     * {@code OPAL_GETACL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OPAL_GETACL"
    )
    OPAL_GETACL,

    /**
     * {@code OPAL_GENKEY = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OPAL_GENKEY"
    )
    OPAL_GENKEY,

    /**
     * {@code OPAL_REVERTSP = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OPAL_REVERTSP"
    )
    OPAL_REVERTSP,

    /**
     * {@code OPAL_GET = 11}
     */
    @EnumMember(
        value = 11L,
        name = "OPAL_GET"
    )
    OPAL_GET,

    /**
     * {@code OPAL_SET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "OPAL_SET"
    )
    OPAL_SET,

    /**
     * {@code OPAL_AUTHENTICATE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "OPAL_AUTHENTICATE"
    )
    OPAL_AUTHENTICATE,

    /**
     * {@code OPAL_RANDOM = 14}
     */
    @EnumMember(
        value = 14L,
        name = "OPAL_RANDOM"
    )
    OPAL_RANDOM,

    /**
     * {@code OPAL_ERASE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "OPAL_ERASE"
    )
    OPAL_ERASE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_token"
  )
  public enum opal_token implements Enum<opal_token>, TypedEnum<opal_token, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_TRUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_TRUE"
    )
    OPAL_TRUE,

    /**
     * {@code OPAL_FALSE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_FALSE"
    )
    OPAL_FALSE,

    /**
     * {@code OPAL_BOOLEAN_EXPR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_BOOLEAN_EXPR"
    )
    OPAL_BOOLEAN_EXPR,

    /**
     * {@code OPAL_TABLE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_TABLE"
    )
    OPAL_TABLE,

    /**
     * {@code OPAL_STARTROW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_STARTROW"
    )
    OPAL_STARTROW,

    /**
     * {@code OPAL_ENDROW = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_ENDROW"
    )
    OPAL_ENDROW,

    /**
     * {@code OPAL_STARTCOLUMN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_STARTCOLUMN"
    )
    OPAL_STARTCOLUMN,

    /**
     * {@code OPAL_ENDCOLUMN = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_ENDCOLUMN"
    )
    OPAL_ENDCOLUMN,

    /**
     * {@code OPAL_VALUES = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_VALUES"
    )
    OPAL_VALUES,

    /**
     * {@code OPAL_TABLE_UID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_TABLE_UID"
    )
    OPAL_TABLE_UID,

    /**
     * {@code OPAL_TABLE_NAME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_TABLE_NAME"
    )
    OPAL_TABLE_NAME,

    /**
     * {@code OPAL_TABLE_COMMON = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_TABLE_COMMON"
    )
    OPAL_TABLE_COMMON,

    /**
     * {@code OPAL_TABLE_TEMPLATE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_TABLE_TEMPLATE"
    )
    OPAL_TABLE_TEMPLATE,

    /**
     * {@code OPAL_TABLE_KIND = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_TABLE_KIND"
    )
    OPAL_TABLE_KIND,

    /**
     * {@code OPAL_TABLE_COLUMN = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OPAL_TABLE_COLUMN"
    )
    OPAL_TABLE_COLUMN,

    /**
     * {@code OPAL_TABLE_COLUMNS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_TABLE_COLUMNS"
    )
    OPAL_TABLE_COLUMNS,

    /**
     * {@code OPAL_TABLE_ROWS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OPAL_TABLE_ROWS"
    )
    OPAL_TABLE_ROWS,

    /**
     * {@code OPAL_TABLE_ROWS_FREE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OPAL_TABLE_ROWS_FREE"
    )
    OPAL_TABLE_ROWS_FREE,

    /**
     * {@code OPAL_TABLE_ROW_BYTES = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OPAL_TABLE_ROW_BYTES"
    )
    OPAL_TABLE_ROW_BYTES,

    /**
     * {@code OPAL_TABLE_LASTID = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OPAL_TABLE_LASTID"
    )
    OPAL_TABLE_LASTID,

    /**
     * {@code OPAL_TABLE_MIN = 11}
     */
    @EnumMember(
        value = 11L,
        name = "OPAL_TABLE_MIN"
    )
    OPAL_TABLE_MIN,

    /**
     * {@code OPAL_TABLE_MAX = 12}
     */
    @EnumMember(
        value = 12L,
        name = "OPAL_TABLE_MAX"
    )
    OPAL_TABLE_MAX,

    /**
     * {@code OPAL_PIN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_PIN"
    )
    OPAL_PIN,

    /**
     * {@code OPAL_RANGESTART = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_RANGESTART"
    )
    OPAL_RANGESTART,

    /**
     * {@code OPAL_RANGELENGTH = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_RANGELENGTH"
    )
    OPAL_RANGELENGTH,

    /**
     * {@code OPAL_READLOCKENABLED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OPAL_READLOCKENABLED"
    )
    OPAL_READLOCKENABLED,

    /**
     * {@code OPAL_WRITELOCKENABLED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_WRITELOCKENABLED"
    )
    OPAL_WRITELOCKENABLED,

    /**
     * {@code OPAL_READLOCKED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OPAL_READLOCKED"
    )
    OPAL_READLOCKED,

    /**
     * {@code OPAL_WRITELOCKED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OPAL_WRITELOCKED"
    )
    OPAL_WRITELOCKED,

    /**
     * {@code OPAL_ACTIVEKEY = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OPAL_ACTIVEKEY"
    )
    OPAL_ACTIVEKEY,

    /**
     * {@code OPAL_LIFECYCLE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OPAL_LIFECYCLE"
    )
    OPAL_LIFECYCLE,

    /**
     * {@code OPAL_MAXRANGES = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_MAXRANGES"
    )
    OPAL_MAXRANGES,

    /**
     * {@code OPAL_MBRENABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_MBRENABLE"
    )
    OPAL_MBRENABLE,

    /**
     * {@code OPAL_MBRDONE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_MBRDONE"
    )
    OPAL_MBRDONE,

    /**
     * {@code OPAL_HOSTPROPERTIES = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_HOSTPROPERTIES"
    )
    OPAL_HOSTPROPERTIES,

    /**
     * {@code OPAL_STARTLIST = 240}
     */
    @EnumMember(
        value = 240L,
        name = "OPAL_STARTLIST"
    )
    OPAL_STARTLIST,

    /**
     * {@code OPAL_ENDLIST = 241}
     */
    @EnumMember(
        value = 241L,
        name = "OPAL_ENDLIST"
    )
    OPAL_ENDLIST,

    /**
     * {@code OPAL_STARTNAME = 242}
     */
    @EnumMember(
        value = 242L,
        name = "OPAL_STARTNAME"
    )
    OPAL_STARTNAME,

    /**
     * {@code OPAL_ENDNAME = 243}
     */
    @EnumMember(
        value = 243L,
        name = "OPAL_ENDNAME"
    )
    OPAL_ENDNAME,

    /**
     * {@code OPAL_CALL = 248}
     */
    @EnumMember(
        value = 248L,
        name = "OPAL_CALL"
    )
    OPAL_CALL,

    /**
     * {@code OPAL_ENDOFDATA = 249}
     */
    @EnumMember(
        value = 249L,
        name = "OPAL_ENDOFDATA"
    )
    OPAL_ENDOFDATA,

    /**
     * {@code OPAL_ENDOFSESSION = 250}
     */
    @EnumMember(
        value = 250L,
        name = "OPAL_ENDOFSESSION"
    )
    OPAL_ENDOFSESSION,

    /**
     * {@code OPAL_STARTTRANSACTON = 251}
     */
    @EnumMember(
        value = 251L,
        name = "OPAL_STARTTRANSACTON"
    )
    OPAL_STARTTRANSACTON,

    /**
     * {@code OPAL_ENDTRANSACTON = 252}
     */
    @EnumMember(
        value = 252L,
        name = "OPAL_ENDTRANSACTON"
    )
    OPAL_ENDTRANSACTON,

    /**
     * {@code OPAL_EMPTYATOM = 255}
     */
    @EnumMember(
        value = 255L,
        name = "OPAL_EMPTYATOM"
    )
    OPAL_EMPTYATOM,

    /**
     * {@code OPAL_WHERE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_WHERE"
    )
    OPAL_WHERE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_parameter"
  )
  public enum opal_parameter implements Enum<opal_parameter>, TypedEnum<opal_parameter, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_SUM_SET_LIST = 393216}
     */
    @EnumMember(
        value = 393216L,
        name = "OPAL_SUM_SET_LIST"
    )
    OPAL_SUM_SET_LIST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_revertlsp"
  )
  public enum opal_revertlsp implements Enum<opal_revertlsp>, TypedEnum<opal_revertlsp, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_KEEP_GLOBAL_RANGE_KEY = 393216}
     */
    @EnumMember(
        value = 393216L,
        name = "OPAL_KEEP_GLOBAL_RANGE_KEY"
    )
    OPAL_KEEP_GLOBAL_RANGE_KEY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_compacket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_compacket extends Struct {
    public @Unsigned @OriginalName("__be32") int reserved0;

    public char @Size(4) [] extendedComID;

    public @Unsigned @OriginalName("__be32") int outstandingData;

    public @Unsigned @OriginalName("__be32") int minTransfer;

    public @Unsigned @OriginalName("__be32") int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_packet"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_packet extends Struct {
    public @Unsigned @OriginalName("__be32") int tsn;

    public @Unsigned @OriginalName("__be32") int hsn;

    public @Unsigned @OriginalName("__be32") int seq_number;

    public @Unsigned @OriginalName("__be16") short reserved0;

    public @Unsigned @OriginalName("__be16") short ack_type;

    public @Unsigned @OriginalName("__be32") int acknowledgment;

    public @Unsigned @OriginalName("__be32") int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_data_subpacket"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_data_subpacket extends Struct {
    public char @Size(6) [] reserved0;

    public @Unsigned @OriginalName("__be16") short kind;

    public @Unsigned @OriginalName("__be32") int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_header extends Struct {
    public opal_compacket cp;

    public opal_packet pkt;

    public opal_data_subpacket subpkt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_step"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_step extends Struct {
    public Ptr<?> fn;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_dev extends Struct {
    public @Unsigned int flags;

    public Ptr<?> data;

    public Ptr<?> send_recv;

    public mutex dev_lock;

    public @Unsigned short comid;

    public @Unsigned int hsn;

    public @Unsigned int tsn;

    public @Unsigned long align;

    public @Unsigned long lowest_lba;

    public @Unsigned int logical_block_size;

    public char align_required;

    public @Unsigned long pos;

    public Ptr<java.lang.Character> cmd;

    public Ptr<java.lang.Character> resp;

    public parsed_resp parsed;

    public @Unsigned long prev_d_len;

    public Ptr<?> prev_data;

    public list_head unlk_lst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum opal_atom_width"
  )
  public enum opal_atom_width implements Enum<opal_atom_width>, TypedEnum<opal_atom_width, java.lang. @Unsigned Integer> {
    /**
     * {@code OPAL_WIDTH_TINY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "OPAL_WIDTH_TINY"
    )
    OPAL_WIDTH_TINY,

    /**
     * {@code OPAL_WIDTH_SHORT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "OPAL_WIDTH_SHORT"
    )
    OPAL_WIDTH_SHORT,

    /**
     * {@code OPAL_WIDTH_MEDIUM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "OPAL_WIDTH_MEDIUM"
    )
    OPAL_WIDTH_MEDIUM,

    /**
     * {@code OPAL_WIDTH_LONG = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OPAL_WIDTH_LONG"
    )
    OPAL_WIDTH_LONG,

    /**
     * {@code OPAL_WIDTH_TOKEN = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OPAL_WIDTH_TOKEN"
    )
    OPAL_WIDTH_TOKEN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_resp_tok"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_resp_tok extends Struct {
    public Ptr<java.lang.Character> pos;

    public @Unsigned long len;

    public opal_response_token type;

    public opal_atom_width width;

    public stored_of_opal_resp_tok stored;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct opal_suspend_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class opal_suspend_data extends Struct {
    public opal_lock_unlock unlk;

    public char lr;

    public list_head node;
  }
}
